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

use crate::error::Result;
use codec::{Decode, Encode};
use ita_stf::{AccountId, TrustedCallSigned};
use itp_settings::node::{CALL_WORKER, SHIELD_FUNDS, TEEREX_MODULE};
use itp_sgx_crypto::ShieldingCrypto;
use itp_stf_executor::traits::{StatePostProcessing, StfExecuteShieldFunds, StfExecuteTrustedCall};
use itp_types::{CallWorkerFn, OpaqueCall, ShardIdentifier, ShieldFundsFn, H256};
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
	) -> Result<(Vec<OpaqueCall>, Vec<H256>)>
	where
		ParentchainBlock: ParentchainBlockTrait<Hash = H256>;
}

pub struct IndirectCallsExecutor<ShieldingKey, StfExecutor> {
	shielding_key: ShieldingKey,
	stf_executor: Arc<StfExecutor>,
}

impl<ShieldingKey, StfExecutor> IndirectCallsExecutor<ShieldingKey, StfExecutor>
where
	ShieldingKey: ShieldingCrypto<Error = itp_sgx_crypto::Error>,
	StfExecutor: StfExecuteTrustedCall + StfExecuteShieldFunds,
{
	pub fn new(authority: ShieldingKey, stf_executor: Arc<StfExecutor>) -> Self {
		IndirectCallsExecutor { shielding_key: authority, stf_executor }
	}

	fn handle_shield_funds_xt(&self, xt: &UncheckedExtrinsicV4<ShieldFundsFn>) -> Result<()> {
		let (call, account_encrypted, amount, shard) = &xt.function;
		info!("Found ShieldFunds extrinsic in block: \nCall: {:?} \nAccount Encrypted {:?} \nAmount: {} \nShard: {}",
        	call, account_encrypted, amount, bs58::encode(shard.encode()).into_string());

		debug!("decrypt the account id");

		let account_vec = self.shielding_key.decrypt(account_encrypted)?;

		let account = AccountId::decode(&mut account_vec.as_slice())?;

		self.stf_executor.execute_shield_funds(account, *amount, shard)?;
		Ok(())
	}

	fn decrypt_unchecked_extrinsic(
		&self,
		xt: UncheckedExtrinsicV4<CallWorkerFn>,
	) -> Result<(TrustedCallSigned, ShardIdentifier)> {
		let (call, request) = xt.function;
		let (shard, cyphertext) = (request.shard, request.cyphertext);
		debug!("Found CallWorker extrinsic in block: \nCall: {:?} \nRequest: \nshard: {}\ncyphertext: {:?}",
        	call, bs58::encode(shard.encode()).into_string(), cyphertext);

		debug!("decrypt the call");
		//let request_vec = Rsa3072KeyPair::decrypt(&cyphertext)?;
		let request_vec = self.shielding_key.decrypt(&cyphertext)?;

		Ok(TrustedCallSigned::decode(&mut request_vec.as_slice()).map(|call| (call, shard))?)
	}
}

impl<ShieldingKey, StfExecutor> ExecuteIndirectCalls
	for IndirectCallsExecutor<ShieldingKey, StfExecutor>
where
	ShieldingKey: ShieldingCrypto<Error = itp_sgx_crypto::Error>,
	StfExecutor: StfExecuteTrustedCall + StfExecuteShieldFunds,
{
	fn execute_indirect_calls_in_extrinsics<ParentchainBlock>(
		&self,
		block: &ParentchainBlock,
	) -> Result<(Vec<OpaqueCall>, Vec<H256>)>
	where
		ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	{
		debug!("Scanning block {:?} for relevant xt", block.header().number());
		let mut opaque_calls = Vec::<OpaqueCall>::new();
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
					if let Ok((decrypted_trusted_call, shard)) =
						self.decrypt_unchecked_extrinsic(xt)
					{
						if let Err(e) = self.stf_executor.execute_trusted_call(
							&mut opaque_calls,
							&decrypted_trusted_call,
							block.header(),
							&shard,
							StatePostProcessing::Prune, // we only want to store the state diff for direct stuff.
						) {
							error!("Error executing trusted call: Error: {:?}", e);
						}
					}
				}
			}
		}
		Ok((opaque_calls, executed_shielding_calls))
	}
}

fn hash_of<T: Encode>(xt: T) -> H256 {
	blake2_256(&xt.encode()).into()
}
