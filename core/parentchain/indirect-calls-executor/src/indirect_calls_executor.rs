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

//! Execute indirect calls, i.e. extrinsics extracted from parentchain blocks

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::error::Result;
use codec::{Decode, Encode};
use futures::executor;
use ita_stf::AccountId;
use itp_settings::node::{
	ACK_GAME, CALL_WORKER, FINISH_GAME, GAME_REGISTRY_MODULE, SHIELD_FUNDS, TEEREX_MODULE,
};
use itp_sgx_crypto::{key_repository::AccessKey, ShieldingCryptoDecrypt};
use itp_stf_executor::traits::StfExecuteShieldFunds;
use itp_top_pool_author::traits::AuthorApi;
use itp_types::{AckGameFn, CallWorkerFn, FinishGameFn, ShieldFundsFn, H256};
use log::*;
use sp_core::blake2_256;
use sp_runtime::traits::{Block as ParentchainBlockTrait, Header};
use std::{sync::Arc, vec::Vec};
use substrate_api_client::UncheckedExtrinsicV4;

/// Trait to execute the indirect calls found in the extrinsics of a block.
pub trait ExecuteIndirectCalls {
	/// Scans blocks for extrinsics that ask the enclave to execute some actions.
	/// Executes indirect invocation calls, including shielding and unshielding calls.
	/// Returns all unshielding call confirmations as opaque calls and the hashes of executed shielding calls.
	fn execute_indirect_calls_in_extrinsics<ParentchainBlock>(
		&self,
		block: &ParentchainBlock,
	) -> Result<Vec<H256>>
	where
		ParentchainBlock: ParentchainBlockTrait<Hash = H256>;
}

pub struct IndirectCallsExecutor<ShieldingKeyRepository, StfExecutor, TopPoolAuthor> {
	shielding_key_repo: Arc<ShieldingKeyRepository>,
	stf_executor: Arc<StfExecutor>,
	top_pool_author: Arc<TopPoolAuthor>,
}

impl<ShieldingKeyRepository, StfExecutor, TopPoolAuthor>
	IndirectCallsExecutor<ShieldingKeyRepository, StfExecutor, TopPoolAuthor>
where
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType:
		ShieldingCryptoDecrypt<Error = itp_sgx_crypto::Error>,
	StfExecutor: StfExecuteShieldFunds,
	TopPoolAuthor: AuthorApi<H256, H256> + Send + Sync + 'static,
{
	pub fn new(
		shielding_key_repo: Arc<ShieldingKeyRepository>,
		stf_executor: Arc<StfExecutor>,
		top_pool_author: Arc<TopPoolAuthor>,
	) -> Self {
		IndirectCallsExecutor { shielding_key_repo, stf_executor, top_pool_author }
	}

	fn handle_shield_funds_xt(&self, xt: &UncheckedExtrinsicV4<ShieldFundsFn>) -> Result<()> {
		let (call, account_encrypted, amount, shard) = &xt.function;
		info!("Found ShieldFunds extrinsic in block: \nCall: {:?} \nAccount Encrypted {:?} \nAmount: {} \nShard: {}",
        	call, account_encrypted, amount, bs58::encode(shard.encode()).into_string());

		debug!("decrypt the account id");

		let shielding_key = self.shielding_key_repo.retrieve_key()?;
		let account_vec = shielding_key.decrypt(account_encrypted)?;

		let account = AccountId::decode(&mut account_vec.as_slice())?;

		self.stf_executor.execute_shield_funds(account, *amount, shard)?;
		Ok(())
	}

	fn handle_ack_game_xt<ParentchainBlock>(
		&self,
		xt: &UncheckedExtrinsicV4<AckGameFn>,
		block: &ParentchainBlock,
	) -> Result<()>
	where
		ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	{
		let (_call, games, shard) = &xt.function;

		info!("found {:?} games", games.len());

		for game in games {
			self.stf_executor.execute_new_game(*game, shard, block)?;
		}
		Ok(())
	}

	fn handle_finish_game_xt<ParentchainBlock>(
		&self,
		xt: &UncheckedExtrinsicV4<FinishGameFn>,
		block: &ParentchainBlock,
	) -> Result<()>
	where
		ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	{
		let (_call, game_id, _winner, shard) = &xt.function;

		info!("handle finish game {}", game_id);

		self.stf_executor.flush_winner(*game_id, shard, block)?;

		Ok(())
	}
}

impl<ShieldingKeyRepository, StfExecutor, TopPoolAuthor> ExecuteIndirectCalls
	for IndirectCallsExecutor<ShieldingKeyRepository, StfExecutor, TopPoolAuthor>
where
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType:
		ShieldingCryptoDecrypt<Error = itp_sgx_crypto::Error>,
	StfExecutor: StfExecuteShieldFunds,
	TopPoolAuthor: AuthorApi<H256, H256> + Send + Sync + 'static,
{
	fn execute_indirect_calls_in_extrinsics<ParentchainBlock>(
		&self,
		block: &ParentchainBlock,
	) -> Result<Vec<H256>>
	where
		ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	{
		debug!("Scanning block {:?} for relevant xt", block.header().number());
		let mut executed_extrinsics = Vec::<H256>::new();
		for xt_opaque in block.extrinsics().iter() {
			// Found ShieldFunds extrinsic in block.
			if let Ok(xt) =
				UncheckedExtrinsicV4::<ShieldFundsFn>::decode(&mut xt_opaque.encode().as_slice())
			{
				if xt.function.0 == [TEEREX_MODULE, SHIELD_FUNDS] {
					if let Err(e) = self.handle_shield_funds_xt(&xt) {
						error!("Error performing shield funds. Error: {:?}", e);
					} else {
						// Cache successfully executed shielding call.
						executed_extrinsics.push(hash_of(xt))
					}
				}
			};

			// Found Ack_Game extrinsic in block.
			if let Ok(xt) =
				UncheckedExtrinsicV4::<AckGameFn>::decode(&mut xt_opaque.encode().as_slice())
			{
				if xt.function.0 == [GAME_REGISTRY_MODULE, ACK_GAME] {
					if let Err(e) = self.handle_ack_game_xt(&xt, block) {
						error!("Error performing acknowledge game. Error: {:?}", e);
					} else {
						// Cache successfully executed shielding call.
						executed_extrinsics.push(hash_of(xt))
					}
				}
			};

			if let Ok(xt) =
				UncheckedExtrinsicV4::<FinishGameFn>::decode(&mut xt_opaque.encode().as_slice())
			{
				if xt.function.0 == [GAME_REGISTRY_MODULE, FINISH_GAME] {
					if let Err(e) = self.handle_finish_game_xt(&xt, block) {
						error!("Error performing finish game. Error: {:?}", e);
					} else {
						// Cache successfully executed shielding call.
						executed_extrinsics.push(hash_of(xt))
					}
				}
			};

			// Found CallWorker extrinsic in block.
			if let Ok(xt) =
				UncheckedExtrinsicV4::<CallWorkerFn>::decode(&mut xt_opaque.encode().as_slice())
			{
				if xt.function.0 == [TEEREX_MODULE, CALL_WORKER] {
					let (_, request) = xt.function;
					let (shard, cypher_text) = (request.shard, request.cyphertext);

					let top_submit_future =
						async { self.top_pool_author.submit_top(cypher_text, shard).await };
					if let Err(e) = executor::block_on(top_submit_future) {
						error!("Error adding indirect trusted call to TOP pool: {:?}", e);
					}
				}
			}
		}
		Ok(executed_extrinsics)
	}
}

fn hash_of<T: Encode>(xt: T) -> H256 {
	blake2_256(&xt.encode()).into()
}

#[cfg(test)]
mod test {
	use super::*;
	use itp_sgx_crypto::mocks::KeyRepositoryMock;
	use itp_stf_executor::mocks::StfExecutorMock;
	use itp_test::{
		builders::parentchain_block_builder::ParentchainBlockBuilder,
		mock::shielding_crypto_mock::ShieldingCryptoMock,
	};
	use itp_top_pool_author::mocks::AuthorApiMock;
	use itp_types::{Request, ShardIdentifier};
	use sp_core::{ed25519, Pair};
	use sp_runtime::{MultiSignature, OpaqueExtrinsic};
	use substrate_api_client::{GenericAddress, GenericExtra};

	type TestShieldingKeyRepo = KeyRepositoryMock<ShieldingCryptoMock>;
	type TestStfExecutor = StfExecutorMock;
	type TestTopPoolAuthor = AuthorApiMock<H256, H256>;
	type TestIndirectCallExecutor =
		IndirectCallsExecutor<TestShieldingKeyRepo, TestStfExecutor, TestTopPoolAuthor>;

	type Seed = [u8; 32];
	const TEST_SEED: Seed = *b"12345678901234567890123456789012";

	#[test]
	fn indirect_call_can_be_added_to_pool_successfully() {
		let _ = env_logger::builder().is_test(true).try_init();

		let (indirect_calls_executor, top_pool_author) = test_fixtures();
		let request = Request { shard: shard_id(), cyphertext: vec![1u8, 2u8] };

		let opaque_extrinsic = OpaqueExtrinsic::from_bytes(
			UncheckedExtrinsicV4::<CallWorkerFn>::new_signed(
				([TEEREX_MODULE, CALL_WORKER], request),
				GenericAddress::Address32([1u8; 32]),
				MultiSignature::Ed25519(default_signature()),
				GenericExtra::default(),
			)
			.encode()
			.as_slice(),
		)
		.unwrap();

		let parentchain_block = ParentchainBlockBuilder::default()
			.with_extrinsics(vec![opaque_extrinsic])
			.build();

		indirect_calls_executor
			.execute_indirect_calls_in_extrinsics(&parentchain_block)
			.unwrap();

		assert_eq!(1, top_pool_author.pending_tops(shard_id()).unwrap().len());
	}

	fn default_signature() -> ed25519::Signature {
		signer().sign(&[0u8])
	}

	fn signer() -> ed25519::Pair {
		ed25519::Pair::from_seed(&TEST_SEED)
	}

	fn shard_id() -> ShardIdentifier {
		ShardIdentifier::default()
	}

	fn test_fixtures() -> (TestIndirectCallExecutor, Arc<TestTopPoolAuthor>) {
		let shielding_key_repo = Arc::new(TestShieldingKeyRepo::default());
		let stf_executor = Arc::new(TestStfExecutor::default());
		let top_pool_author = Arc::new(TestTopPoolAuthor::default());

		let executor =
			IndirectCallsExecutor::new(shielding_key_repo, stf_executor, top_pool_author.clone());

		(executor, top_pool_author)
	}
}
