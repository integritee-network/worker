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

use crate::{error::Result, IndirectDispatch, IndirectExecutor};
use codec::{Decode, Encode};
use ita_stf::{TrustedCall, TrustedOperation};
use itp_stf_primitives::types::AccountId;
use itp_types::{Balance, ShardIdentifier};
use log::{debug, info};
use std::vec::Vec;

/// Arguments of the Integritee-Parachain's shield fund dispatchable.
#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub struct ShieldFundsArgs {
	shard: ShardIdentifier,
	account_encrypted: Vec<u8>,
	amount: Balance,
}

impl<Executor: IndirectExecutor> IndirectDispatch<Executor> for ShieldFundsArgs {
	fn dispatch(&self, executor: &Executor) -> Result<()> {
		info!("Found ShieldFunds extrinsic in block: \nAccount Encrypted {:?} \nAmount: {} \nShard: {}",
        	self.account_encrypted, self.amount, bs58::encode(self.shard.encode()).into_string());

		debug!("decrypt the account id");
		let account_vec = executor.decrypt(&self.account_encrypted)?;
		let account = AccountId::decode(&mut account_vec.as_slice())?;

		let enclave_account_id = executor.get_enclave_account()?;
		let trusted_call = TrustedCall::balance_shield(enclave_account_id, account, self.amount);
		let signed_trusted_call = executor.sign_call_with_self(&trusted_call, &self.shard)?;
		let trusted_operation = TrustedOperation::indirect_call(signed_trusted_call);

		let encrypted_trusted_call = executor.encrypt(&trusted_operation.encode())?;
		executor.submit_trusted_call(self.shard, encrypted_trusted_call);
		Ok(())
	}
}
