/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/

//! Aura worker for the sidechain.
//!
//! It is inspired by parity's implementation but has been greatly amended.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, feature(assert_matches))]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use core::marker::PhantomData;
use itc_parentchain_block_import_dispatcher::triggered_dispatcher::TriggerParentchainBlockImport;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_time_utils::duration_now;
use its_block_verification::slot::slot_author;
use its_consensus_common::{Environment, Error as ConsensusError, Proposer};
use its_consensus_slots::{SimpleSlotWorker, Slot, SlotInfo};
use its_primitives::{
	traits::{Block as SidechainBlockTrait, Header as HeaderTrait, SignedBlock},
	types::block::BlockHash,
};
use its_validateer_fetch::ValidateerFetch;
use sp_core::ByteArray;
use sp_runtime::{
	app_crypto::{sp_core::H256, Pair},
	generic::SignedBlock as SignedParentchainBlock,
	traits::{Block as ParentchainBlockTrait, Header as ParentchainHeaderTrait},
};
use std::{string::ToString, sync::Arc, time::Duration, vec::Vec};

pub mod block_importer;
pub mod proposer_factory;
pub mod slot_proposer;
mod verifier;

pub use verifier::*;

#[cfg(test)]
mod test;

/// Aura consensus struct.
pub struct Aura<
	AuthorityPair,
	ParentchainBlock,
	SidechainBlock,
	Environment,
	OcallApi,
	ImportTrigger,
> {
	authority_pair: AuthorityPair,
	ocall_api: OcallApi,
	parentchain_import_trigger: Arc<ImportTrigger>,
	environment: Environment,
	claim_strategy: SlotClaimStrategy,
	_phantom: PhantomData<(AuthorityPair, ParentchainBlock, SidechainBlock)>,
}

impl<AuthorityPair, ParentchainBlock, SidechainBlock, Environment, OcallApi, ImportTrigger>
	Aura<AuthorityPair, ParentchainBlock, SidechainBlock, Environment, OcallApi, ImportTrigger>
{
	pub fn new(
		authority_pair: AuthorityPair,
		ocall_api: OcallApi,
		parentchain_import_trigger: Arc<ImportTrigger>,
		environment: Environment,
	) -> Self {
		Self {
			authority_pair,
			ocall_api,
			parentchain_import_trigger,
			environment,
			claim_strategy: SlotClaimStrategy::RoundRobin,
			_phantom: Default::default(),
		}
	}

	pub fn with_claim_strategy(mut self, claim_strategy: SlotClaimStrategy) -> Self {
		self.claim_strategy = claim_strategy;

		self
	}
}

/// The fraction of total block time we are allowed to be producing the block. So that we have
/// enough time send create and send the block to fellow validateers.
pub const BLOCK_PROPOSAL_SLOT_PORTION: f32 = 0.7;

#[derive(PartialEq, Eq, Debug)]
pub enum SlotClaimStrategy {
	/// try to produce a block always even if it's not the authors slot
	/// Intended for first phase to see if aura production works
	Always,
	/// Proper Aura strategy: Only produce blocks, when it's the authors slot.
	RoundRobin,
}

type AuthorityId<P> = <P as Pair>::Public;
type ShardIdentifierFor<SignedSidechainBlock> =
	<<<SignedSidechainBlock as SignedBlock>::Block as SidechainBlockTrait>::HeaderType as HeaderTrait>::ShardIdentifier;

impl<AuthorityPair, ParentchainBlock, SignedSidechainBlock, E, OcallApi, ImportTrigger>
	SimpleSlotWorker<ParentchainBlock>
	for Aura<AuthorityPair, ParentchainBlock, SignedSidechainBlock, E, OcallApi, ImportTrigger>
where
	AuthorityPair: Pair,
	// todo: Relax hash trait bound, but this needs a change to some other parts in the code.
	ParentchainBlock: ParentchainBlockTrait<Hash = BlockHash>,
	E: Environment<ParentchainBlock, SignedSidechainBlock, Error = ConsensusError>,
	E::Proposer: Proposer<ParentchainBlock, SignedSidechainBlock>,
	SignedSidechainBlock: SignedBlock + Send + 'static,
	OcallApi: ValidateerFetch + EnclaveOnChainOCallApi + Send + 'static,
	ImportTrigger:
		TriggerParentchainBlockImport<SignedBlockType = SignedParentchainBlock<ParentchainBlock>>,
{
	type Proposer = E::Proposer;
	type Claim = AuthorityPair::Public;
	type EpochData = Vec<AuthorityId<AuthorityPair>>;
	type Output = SignedSidechainBlock;

	fn logging_target(&self) -> &'static str {
		"aura"
	}

	fn epoch_data(
		&self,
		header: &ParentchainBlock::Header,
		_slot: Slot,
	) -> Result<Self::EpochData, ConsensusError> {
		authorities::<_, AuthorityPair, ParentchainBlock::Header>(&self.ocall_api, header)
	}

	fn authorities_len(&self, epoch_data: &Self::EpochData) -> Option<usize> {
		Some(epoch_data.len())
	}

	// While the header is not used in aura, it is used in different consensus systems, so it should be left there.
	fn claim_slot(
		&self,
		_header: &ParentchainBlock::Header,
		slot: Slot,
		epoch_data: &Self::EpochData,
	) -> Option<Self::Claim> {
		let expected_author = slot_author::<AuthorityPair>(slot, epoch_data)?;

		if expected_author == &self.authority_pair.public() {
			log::info!(target: self.logging_target(), "Claiming slot ({})", *slot);
			return Some(self.authority_pair.public())
		}

		if self.claim_strategy == SlotClaimStrategy::Always {
			log::debug!(
				target: self.logging_target(),
				"Not our slot but we still claim it."
			);
			return Some(self.authority_pair.public())
		}

		None
	}

	fn proposer(
		&mut self,
		header: ParentchainBlock::Header,
		shard: ShardIdentifierFor<Self::Output>,
	) -> Result<Self::Proposer, ConsensusError> {
		self.environment.init(header, shard)
	}

	fn proposing_remaining_duration(&self, slot_info: &SlotInfo<ParentchainBlock>) -> Duration {
		proposing_remaining_duration(slot_info, duration_now())
	}

	fn import_parentchain_blocks_until(
		&self,
		parentchain_header_hash: &<ParentchainBlock::Header as ParentchainHeaderTrait>::Hash,
	) -> Result<Option<ParentchainBlock::Header>, ConsensusError> {
		let maybe_parentchain_block = self
			.parentchain_import_trigger
			.import_until(|parentchain_block| {
				parentchain_block.block.hash() == *parentchain_header_hash
			})
			.map_err(|e| ConsensusError::Other(e.into()))?;

		Ok(maybe_parentchain_block.map(|b| b.block.header().clone()))
	}

	fn peek_latest_parentchain_header(
		&self,
	) -> Result<Option<ParentchainBlock::Header>, ConsensusError> {
		let maybe_parentchain_block = self
			.parentchain_import_trigger
			.peek_latest()
			.map_err(|e| ConsensusError::Other(format!("{:?}", e).into()))?;

		Ok(maybe_parentchain_block.map(|b| b.block.header().clone()))
	}
}

/// unit-testable remaining duration fn.
fn proposing_remaining_duration<ParentchainBlock: ParentchainBlockTrait>(
	slot_info: &SlotInfo<ParentchainBlock>,
	now: Duration,
) -> Duration {
	// if a `now` before slot begin is passed such that `slot_remaining` would be bigger than `slot.slot_duration`
	// we take the total `slot_duration` as reference value.
	let proposing_duration = slot_info.duration.mul_f32(BLOCK_PROPOSAL_SLOT_PORTION);

	let slot_remaining = slot_info
		.ends_at
		.checked_sub(now)
		.map(|remaining| remaining.mul_f32(BLOCK_PROPOSAL_SLOT_PORTION))
		.unwrap_or_default();

	std::cmp::min(slot_remaining, proposing_duration)
}

fn authorities<ValidateerFetcher, P, ParentchainHeader>(
	ocall_api: &ValidateerFetcher,
	header: &ParentchainHeader,
) -> Result<Vec<AuthorityId<P>>, ConsensusError>
where
	ValidateerFetcher: ValidateerFetch + EnclaveOnChainOCallApi,
	P: Pair,
	ParentchainHeader: ParentchainHeaderTrait<Hash = H256>,
{
	Ok(ocall_api
		.current_validateers(header)
		.map_err(|e| ConsensusError::CouldNotGetAuthorities(e.to_string()))?
		.into_iter()
		.filter_map(|e| AuthorityId::<P>::from_slice(e.pubkey.as_ref()).ok())
		.collect())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test::{
		fixtures::{types::TestAura, validateer, SLOT_DURATION},
		mocks::environment_mock::EnvironmentMock,
	};
	use itc_parentchain_block_import_dispatcher::trigger_parentchain_block_import_mock::TriggerParentchainBlockImportMock;
	use itc_parentchain_test::{ParentchainBlockBuilder, ParentchainHeaderBuilder};
	use itp_test::mock::onchain_mock::OnchainMock;
	use itp_types::{
		Block as ParentchainBlock, Enclave, Header as ParentchainHeader,
		SignedBlock as SignedParentchainBlock,
	};
	use its_consensus_slots::PerShardSlotWorkerScheduler;
	use sp_core::ed25519::Public;
	use sp_keyring::ed25519::Keyring;

	fn get_aura(
		onchain_mock: OnchainMock,
		trigger_parentchain_import: Arc<TriggerParentchainBlockImportMock<SignedParentchainBlock>>,
	) -> TestAura {
		Aura::new(Keyring::Alice.pair(), onchain_mock, trigger_parentchain_import, EnvironmentMock)
	}

	fn get_default_aura() -> TestAura {
		get_aura(Default::default(), Default::default())
	}

	fn now_slot(slot: Slot, header: &ParentchainHeader) -> SlotInfo<ParentchainBlock> {
		let now = duration_now();
		SlotInfo {
			slot,
			timestamp: now,
			duration: SLOT_DURATION,
			ends_at: now + SLOT_DURATION,
			last_imported_parentchain_head: header.clone(),
		}
	}

	fn now_slot_with_default_header(slot: Slot) -> SlotInfo<ParentchainBlock> {
		now_slot(slot, &ParentchainHeaderBuilder::default().build())
	}

	fn default_authorities() -> Vec<Public> {
		vec![Keyring::Alice.public(), Keyring::Bob.public(), Keyring::Charlie.public()]
	}

	fn create_validateer_set_from_publics(authorities: Vec<Public>) -> Vec<Enclave> {
		authorities.iter().map(|a| validateer(a.clone().into())).collect()
	}

	fn onchain_mock(
		parentchain_header: &ParentchainHeader,
		authorities: Vec<Public>,
	) -> OnchainMock {
		let validateers = create_validateer_set_from_publics(authorities);
		OnchainMock::default().add_validateer_set(parentchain_header, Some(validateers))
	}

	fn onchain_mock_with_default_authorities_and_header() -> OnchainMock {
		let parentchain_header = ParentchainHeaderBuilder::default().build();
		onchain_mock(&parentchain_header, default_authorities())
	}

	fn create_import_trigger_with_header(
		header: ParentchainHeader,
	) -> Arc<TriggerParentchainBlockImportMock<SignedParentchainBlock>> {
		let latest_parentchain_block =
			ParentchainBlockBuilder::default().with_header(header).build_signed();
		Arc::new(
			TriggerParentchainBlockImportMock::default()
				.with_latest_imported(Some(latest_parentchain_block)),
		)
	}

	#[test]
	fn current_authority_should_claim_its_slot() {
		let authorities =
			vec![Keyring::Bob.public(), Keyring::Charlie.public(), Keyring::Alice.public()];
		let aura = get_default_aura();
		let header = ParentchainHeaderBuilder::default().build();

		assert!(aura.claim_slot(&header, 0.into(), &authorities).is_none());
		assert!(aura.claim_slot(&header, 1.into(), &authorities).is_none());
		// this our authority
		assert!(aura.claim_slot(&header, 2.into(), &authorities).is_some());

		assert!(aura.claim_slot(&header, 3.into(), &authorities).is_none());
		assert!(aura.claim_slot(&header, 4.into(), &authorities).is_none());
		// this our authority
		assert!(aura.claim_slot(&header, 5.into(), &authorities).is_some());
	}

	#[test]
	fn current_authority_should_claim_all_slots() {
		let header = ParentchainHeaderBuilder::default().build();
		let authorities = default_authorities();
		let aura = get_default_aura().with_claim_strategy(SlotClaimStrategy::Always);

		assert!(aura.claim_slot(&header, 0.into(), &authorities).is_some());
		assert!(aura.claim_slot(&header, 1.into(), &authorities).is_some());
		// this our authority
		assert!(aura.claim_slot(&header, 2.into(), &authorities).is_some());
		assert!(aura.claim_slot(&header, 3.into(), &authorities).is_some());
	}

	#[test]
	fn on_slot_returns_block() {
		let _ = env_logger::builder().is_test(true).try_init();

		let onchain_mock = onchain_mock_with_default_authorities_and_header();
		let mut aura = get_aura(onchain_mock, Default::default());

		let slot_info = now_slot_with_default_header(0.into());

		assert!(SimpleSlotWorker::on_slot(&mut aura, slot_info, Default::default()).is_some());
	}

	#[test]
	fn on_slot_for_multiple_shards_returns_blocks() {
		let _ = env_logger::builder().is_test(true).try_init();

		let onchain_mock = onchain_mock_with_default_authorities_and_header();
		let mut aura = get_aura(onchain_mock, Default::default());

		let slot_info = now_slot_with_default_header(0.into());

		let result = PerShardSlotWorkerScheduler::on_slot(
			&mut aura,
			slot_info,
			vec![Default::default(), Default::default()],
		);

		assert_eq!(result.len(), 2);
	}

	#[test]
	fn on_slot_with_nano_second_remaining_duration_does_not_panic() {
		let _ = env_logger::builder().is_test(true).try_init();

		let mut aura = get_default_aura();

		let nano_dur = Duration::from_nanos(999);
		let now = duration_now();

		let slot_info = SlotInfo {
			slot: 0.into(),
			timestamp: now,
			duration: nano_dur,
			ends_at: now + nano_dur,
			last_imported_parentchain_head: ParentchainHeaderBuilder::default().build(),
		};

		let result = PerShardSlotWorkerScheduler::on_slot(
			&mut aura,
			slot_info,
			vec![Default::default(), Default::default()],
		);

		assert_eq!(result.len(), 0);
	}

	#[test]
	fn on_slot_triggers_parentchain_block_import_if_slot_is_claimed() {
		let _ = env_logger::builder().is_test(true).try_init();
		let latest_parentchain_header = ParentchainHeaderBuilder::default().with_number(84).build();
		let parentchain_block_import_trigger =
			create_import_trigger_with_header(latest_parentchain_header.clone());
		let authorities = default_authorities();

		let mut aura = get_aura(
			onchain_mock(&latest_parentchain_header, authorities),
			parentchain_block_import_trigger.clone(),
		);

		let slot_info = now_slot(0.into(), &latest_parentchain_header);

		let result = SimpleSlotWorker::on_slot(&mut aura, slot_info, Default::default()).unwrap();

		assert_eq!(
			result.block.block.block_data().layer_one_head,
			latest_parentchain_header.hash()
		);
		assert!(parentchain_block_import_trigger.has_import_been_called());
	}

	#[test]
	fn on_slot_does_not_trigger_parentchain_block_import_if_slot_is_not_claimed() {
		let _ = env_logger::builder().is_test(true).try_init();
		let latest_parentchain_header = ParentchainHeaderBuilder::default().with_number(84).build();
		let parentchain_block_import_trigger =
			create_import_trigger_with_header(latest_parentchain_header.clone());
		let authorities = default_authorities();

		let mut aura = get_aura(
			onchain_mock(&latest_parentchain_header, authorities),
			parentchain_block_import_trigger.clone(),
		);

		let slot_info = now_slot(2.into(), &latest_parentchain_header);

		let result = SimpleSlotWorker::on_slot(&mut aura, slot_info, Default::default());

		assert!(result.is_none());
		assert!(!parentchain_block_import_trigger.has_import_been_called());
	}

	#[test]
	fn on_slot_claims_slot_if_latest_parentchain_header_in_queue_contains_correspondent_validateer_set(
	) {
		let _ = env_logger::builder().is_test(true).try_init();
		let already_imported_parentchain_header =
			ParentchainHeaderBuilder::default().with_number(84).build();
		let latest_parentchain_header = ParentchainHeaderBuilder::default().with_number(85).build();
		let parentchain_block_import_trigger =
			create_import_trigger_with_header(latest_parentchain_header.clone());
		let validateer_set_one = create_validateer_set_from_publics(vec![
			Keyring::Alice.public(),
			Keyring::Bob.public(),
		]);
		let validateer_set_two = create_validateer_set_from_publics(vec![
			Keyring::Alice.public(),
			Keyring::Bob.public(),
			Keyring::Charlie.public(),
		]);
		let onchain_mock = OnchainMock::default()
			.add_validateer_set(&already_imported_parentchain_header, Some(validateer_set_one))
			.add_validateer_set(&latest_parentchain_header, Some(validateer_set_two));

		let mut aura = get_aura(onchain_mock, parentchain_block_import_trigger.clone());

		let slot_info = now_slot(3.into(), &already_imported_parentchain_header);

		let result = SimpleSlotWorker::on_slot(&mut aura, slot_info, Default::default()).unwrap();

		assert_eq!(
			result.block.block.block_data().layer_one_head,
			latest_parentchain_header.hash()
		);
		assert!(parentchain_block_import_trigger.has_import_been_called());
	}

	#[test]
	fn on_slot_does_not_claim_slot_if_latest_parentchain_header_in_queue_contains_correspondent_validateer_set(
	) {
		let _ = env_logger::builder().is_test(true).try_init();
		let already_imported_parentchain_header =
			ParentchainHeaderBuilder::default().with_number(84).build();
		let latest_parentchain_header = ParentchainHeaderBuilder::default().with_number(85).build();
		let parentchain_block_import_trigger =
			create_import_trigger_with_header(latest_parentchain_header.clone());
		let validateer_set_one = create_validateer_set_from_publics(vec![
			Keyring::Alice.public(),
			Keyring::Bob.public(),
		]);
		let validateer_set_two = create_validateer_set_from_publics(vec![
			Keyring::Alice.public(),
			Keyring::Bob.public(),
			Keyring::Charlie.public(),
		]);
		let onchain_mock = OnchainMock::default()
			.add_validateer_set(&already_imported_parentchain_header, Some(validateer_set_one))
			.add_validateer_set(&latest_parentchain_header, Some(validateer_set_two));

		let mut aura = get_aura(onchain_mock, parentchain_block_import_trigger.clone());

		// If the validateer set one (instead of the latest one) is looked up, the slot will be claimed. But it should not, as the latest one should be used.
		let slot_info = now_slot(2.into(), &already_imported_parentchain_header);
		let result = SimpleSlotWorker::on_slot(&mut aura, slot_info, Default::default());

		assert!(result.is_none());
		assert!(!parentchain_block_import_trigger.has_import_been_called());
	}

	#[test]
	fn proposing_remaining_duration_works() {
		let slot_info = now_slot_with_default_header(0.into());

		// hard to compare actual numbers but we can at least ensure that the general concept works
		assert!(
			proposing_remaining_duration(&slot_info, duration_now())
				< SLOT_DURATION.mul_f32(BLOCK_PROPOSAL_SLOT_PORTION + 0.01)
		);
	}

	#[test]
	fn proposing_remaining_duration_works_for_now_before_slot_timestamp() {
		let slot_info = now_slot_with_default_header(0.into());

		assert!(
			proposing_remaining_duration(&slot_info, Duration::from_millis(0))
				< SLOT_DURATION.mul_f32(BLOCK_PROPOSAL_SLOT_PORTION + 0.01)
		);
	}

	#[test]
	fn proposing_remaining_duration_returns_default_if_now_after_slot() {
		let slot_info = now_slot_with_default_header(0.into());

		assert_eq!(
			proposing_remaining_duration(&slot_info, duration_now() + SLOT_DURATION),
			Default::default()
		);
	}
}
