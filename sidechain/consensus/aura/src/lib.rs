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
use itp_storage_verifier::GetStorageVerified;
use itp_time_utils::duration_now;
use its_consensus_common::{Environment, Error as ConsensusError, Proposer};
use its_consensus_slots::{SimpleSlotWorker, Slot, SlotInfo};
use its_primitives::{
	traits::{Block as SidechainBlockT, SignedBlock},
	types::block::BlockHash,
};
use its_validateer_fetch::ValidateerFetch;
use sp_runtime::{
	app_crypto::{sp_core::H256, Pair, Public},
	traits::Block as ParentchainBlock,
};
use std::{string::ToString, time::Duration, vec::Vec};

pub mod block_importer;
pub mod proposer_factory;
pub mod slot_proposer;
mod verifier;

pub use verifier::*;

#[cfg(test)]
mod mock;

/// Aura consensus struct.
pub struct Aura<AuthorityPair, ParentchainBlock, SidechainBlock, Environment, OcallApi> {
	authority_pair: AuthorityPair,
	ocall_api: OcallApi,
	environment: Environment,
	claim_strategy: SlotClaimStrategy,
	/// Remove when #447 is resolved.
	allow_delayed_proposal: bool,
	_phantom: PhantomData<(AuthorityPair, ParentchainBlock, SidechainBlock)>,
}

impl<AuthorityPair, ParentchainBlock, SidechainBlock, Environment, OcallApi>
	Aura<AuthorityPair, ParentchainBlock, SidechainBlock, Environment, OcallApi>
{
	pub fn new(
		authority_pair: AuthorityPair,
		ocall_api: OcallApi,
		environment: Environment,
	) -> Self {
		Self {
			authority_pair,
			ocall_api,
			environment,
			claim_strategy: SlotClaimStrategy::RoundRobin,
			allow_delayed_proposal: false,
			_phantom: Default::default(),
		}
	}

	pub fn with_claim_strategy(mut self, claim_strategy: SlotClaimStrategy) -> Self {
		self.claim_strategy = claim_strategy;

		self
	}

	pub fn with_allow_delayed_proposal(mut self, allow_delayed: bool) -> Self {
		self.allow_delayed_proposal = allow_delayed;

		self
	}
}

/// The fraction of total block time we are allowed to be producing the block. So that we have
/// enough time send create and send the block to fellow validateers.
pub const BLOCK_PROPOSAL_SLOT_PORTION: f32 = 0.8;

#[derive(PartialEq, Eq, Debug)]
pub enum SlotClaimStrategy {
	/// try to produce a block always even if it's not the authors slot
	/// Intended for first phase to see if aura production works
	Always,
	/// Proper Aura strategy: Only produce blocks, when it's the authors slot.
	RoundRobin,
}

type AuthorityId<P> = <P as Pair>::Public;
type ShardIdentifierFor<SB> = <<SB as SignedBlock>::Block as SidechainBlockT>::ShardIdentifier;

impl<AuthorityPair, PB, SB, E, OcallApi> SimpleSlotWorker<PB>
	for Aura<AuthorityPair, PB, SB, E, OcallApi>
where
	AuthorityPair: Pair,
	// todo: Relax hash trait bound, but this needs a change to some other parts in the code.
	PB: ParentchainBlock<Hash = BlockHash>,
	E: Environment<PB, SB, Error = ConsensusError>,
	E::Proposer: Proposer<PB, SB>,
	SB: SignedBlock + Send + 'static,
	OcallApi: ValidateerFetch + GetStorageVerified + Send + 'static,
{
	type Proposer = E::Proposer;
	type Claim = AuthorityPair::Public;
	type EpochData = Vec<AuthorityId<AuthorityPair>>;
	type Output = SB;

	fn logging_target(&self) -> &'static str {
		"aura"
	}

	fn epoch_data(
		&self,
		header: &PB::Header,
		_slot: Slot,
	) -> Result<Self::EpochData, ConsensusError> {
		authorities::<_, AuthorityPair, PB>(&self.ocall_api, header)
	}

	fn authorities_len(&self, epoch_data: &Self::EpochData) -> Option<usize> {
		Some(epoch_data.len())
	}

	fn claim_slot(
		&self,
		_header: &PB::Header,
		slot: Slot,
		epoch_data: &Self::EpochData,
	) -> Option<Self::Claim> {
		let expected_author = slot_author::<AuthorityPair>(slot, epoch_data)?;

		if expected_author == &self.authority_pair.public() {
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
		header: PB::Header,
		shard: ShardIdentifierFor<Self::Output>,
	) -> Result<Self::Proposer, ConsensusError> {
		self.environment.init(header, shard)
	}

	fn allow_delayed_proposal(&self) -> bool {
		self.allow_delayed_proposal
	}

	fn proposing_remaining_duration(&self, slot_info: &SlotInfo<PB>) -> Duration {
		proposing_remaining_duration(slot_info, duration_now())
	}
}

/// unit-testable remaining duration fn.
fn proposing_remaining_duration<PB: ParentchainBlock>(
	slot_info: &SlotInfo<PB>,
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

fn authorities<C, P, B>(
	ocall_api: &C,
	header: &B::Header,
) -> Result<Vec<AuthorityId<P>>, ConsensusError>
where
	C: ValidateerFetch + GetStorageVerified,
	P: Pair,
	B: ParentchainBlock<Hash = H256>,
{
	Ok(ocall_api
		.current_validateers(header)
		.map_err(|e| ConsensusError::CouldNotGetAuthorities(e.to_string()))?
		.into_iter()
		.map(|e| AuthorityId::<P>::from_slice(e.pubkey.as_ref()))
		.collect())
}

/// Get slot author for given block along with authorities.
fn slot_author<P: Pair>(slot: Slot, authorities: &[AuthorityId<P>]) -> Option<&AuthorityId<P>> {
	if authorities.is_empty() {
		return None
	}

	let idx = *slot % (authorities.len() as u64);
	assert!(
		idx <= usize::MAX as u64,
		"It is impossible to have a vector with length beyond the address space; qed",
	);

	let current_author = authorities.get(idx as usize).expect(
		"authorities not empty; index constrained to list length;this is a valid index; qed",
	);

	Some(current_author)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mock::{default_header, validateer, EnvironmentMock, TestAura, SLOT_DURATION};
	use itp_test::mock::onchain_mock::OnchainMock;
	use itp_types::Block as ParentchainBlock;
	use its_consensus_slots::PerShardSlotWorkerScheduler;
	use sp_keyring::ed25519::Keyring;

	fn get_aura(onchain_mock: OnchainMock) -> TestAura {
		Aura::new(Keyring::Alice.pair(), onchain_mock, EnvironmentMock)
	}

	fn now_slot(slot: Slot) -> SlotInfo<ParentchainBlock> {
		SlotInfo {
			slot,
			timestamp: duration_now(),
			duration: SLOT_DURATION,
			ends_at: duration_now() + SLOT_DURATION,
			parentchain_head: default_header(),
		}
	}

	#[test]
	fn current_authority_should_claim_its_slot() {
		let authorities = vec![
			Keyring::Bob.public().into(),
			Keyring::Charlie.public().into(),
			Keyring::Alice.public().into(),
		];

		let aura = get_aura(Default::default());

		assert!(aura.claim_slot(&default_header(), 0.into(), &authorities).is_none());
		assert!(aura.claim_slot(&default_header(), 1.into(), &authorities).is_none());
		// this our authority
		assert!(aura.claim_slot(&default_header(), 2.into(), &authorities).is_some());

		assert!(aura.claim_slot(&default_header(), 3.into(), &authorities).is_none());
		assert!(aura.claim_slot(&default_header(), 4.into(), &authorities).is_none());
		// this our authority
		assert!(aura.claim_slot(&default_header(), 5.into(), &authorities).is_some());
	}

	#[test]
	fn current_authority_should_claim_all_slots() {
		let authorities = vec![
			Keyring::Bob.public().into(),
			Keyring::Charlie.public().into(),
			Keyring::Alice.public().into(),
		];

		let aura = get_aura(Default::default()).with_claim_strategy(SlotClaimStrategy::Always);

		assert!(aura.claim_slot(&default_header(), 0.into(), &authorities).is_some());
		assert!(aura.claim_slot(&default_header(), 1.into(), &authorities).is_some());
		// this our authority
		assert!(aura.claim_slot(&default_header(), 2.into(), &authorities).is_some());
		assert!(aura.claim_slot(&default_header(), 3.into(), &authorities).is_some());
	}

	#[test]
	fn on_slot_returns_block() {
		let _ = env_logger::builder().is_test(true).try_init();

		let onchain_mock = OnchainMock::default().with_validateer_set(Some(vec![
			validateer(Keyring::Alice.public().into()),
			validateer(Keyring::Bob.public().into()),
			validateer(Keyring::Charlie.public().into()),
		]));
		let mut aura = get_aura(onchain_mock);

		let slot_info = SlotInfo {
			slot: 0.into(),
			timestamp: duration_now(),
			duration: SLOT_DURATION,
			ends_at: duration_now() + SLOT_DURATION,
			parentchain_head: default_header(),
		};

		assert!(SimpleSlotWorker::on_slot(&mut aura, slot_info, Default::default()).is_some());
	}

	#[test]
	fn on_slot_for_multiple_shards_returns_blocks() {
		let _ = env_logger::builder().is_test(true).try_init();

		let onchain_mock = OnchainMock::default().with_validateer_set(Some(vec![
			validateer(Keyring::Alice.public().into()),
			validateer(Keyring::Bob.public().into()),
			validateer(Keyring::Charlie.public().into()),
		]));
		let mut aura = get_aura(onchain_mock);

		let slot_info = SlotInfo {
			slot: 0.into(),
			timestamp: duration_now(),
			duration: SLOT_DURATION,
			ends_at: duration_now() + SLOT_DURATION,
			parentchain_head: default_header(),
		};

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

		let mut aura = get_aura(OnchainMock::default());

		let nano_dur = Duration::from_nanos(999);
		let now = duration_now();

		let slot_info = SlotInfo {
			slot: 0.into(),
			timestamp: now,
			duration: nano_dur,
			ends_at: now + nano_dur,
			parentchain_head: default_header(),
		};

		let result = PerShardSlotWorkerScheduler::on_slot(
			&mut aura,
			slot_info,
			vec![Default::default(), Default::default()],
		);

		assert_eq!(result.len(), 0);
	}

	#[test]
	fn proposing_remaining_duration_works() {
		let slot_info = now_slot(0.into());

		// hard to compare actual numbers but we can at least ensure that the general concept works
		assert!(
			proposing_remaining_duration(&slot_info, duration_now()) > SLOT_DURATION / 2
				&& proposing_remaining_duration(&slot_info, duration_now())
					< SLOT_DURATION.mul_f32(BLOCK_PROPOSAL_SLOT_PORTION + 0.01)
		);
	}

	#[test]
	fn proposing_remaining_duration_works_for_now_before_slot_timestamp() {
		let slot_info = now_slot(0.into());

		assert!(
			proposing_remaining_duration(&slot_info, Duration::from_millis(0)) > SLOT_DURATION / 2
				&& proposing_remaining_duration(&slot_info, Duration::from_millis(0))
					< SLOT_DURATION.mul_f32(BLOCK_PROPOSAL_SLOT_PORTION + 0.01)
		);
	}

	#[test]
	fn proposing_remaining_duration_returns_default_if_now_after_slot() {
		let slot_info = now_slot(0.into());

		assert_eq!(
			proposing_remaining_duration(&slot_info, duration_now() + SLOT_DURATION),
			Default::default()
		);
	}
}
