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
use itp_settings::node::{CALL_WORKER, SHIELD_FUNDS, TEEREX_MODULE};
use itp_sgx_crypto::{key_repository::AccessKey, ShieldingCryptoDecrypt};
use itp_stf_executor::traits::{StfExecuteShieldFunds, StfExecuteTrustedCall};
use itp_top_pool_author::traits::AuthorApi;
use itp_types::{CallWorkerFn, ShieldFundsFn, H256};
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
	StfExecutor: StfExecuteTrustedCall + StfExecuteShieldFunds,
	TopPoolAuthor: AuthorApi<H256, H256> + Send + Sync + 'static,
{
	pub fn new(
		authority: Arc<ShieldingKeyRepository>,
		stf_executor: Arc<StfExecutor>,
		top_pool_author: Arc<TopPoolAuthor>,
	) -> Self {
		IndirectCallsExecutor { shielding_key_repo: authority, stf_executor, top_pool_author }
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
}

impl<ShieldingKeyRepository, StfExecutor, TopPoolAuthor> ExecuteIndirectCalls
	for IndirectCallsExecutor<ShieldingKeyRepository, StfExecutor, TopPoolAuthor>
where
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType:
		ShieldingCryptoDecrypt<Error = itp_sgx_crypto::Error>,
	StfExecutor: StfExecuteTrustedCall + StfExecuteShieldFunds,
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
		let mut executed_shielding_calls = Vec::<H256>::new();
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
						executed_shielding_calls.push(hash_of(xt))
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
		Ok(executed_shielding_calls)
	}
}

fn hash_of<T: Encode>(xt: T) -> H256 {
	blake2_256(&xt.encode()).into()
}
