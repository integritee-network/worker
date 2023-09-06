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
use itp_types::Balance;
use log::info;
use sp_core::Pair;

/// Arguments of a parentchains `transfer` or `transfer_allow_death` dispatchable.
///
/// This is a simple demo indirect call where a transfer to alice on chain will transfer
/// funds to alice on sidechain.
#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub struct TransferToAliceShieldsFundsArgs {
	pub destination: AccountId,
	pub value: Balance,
}

type Seed = [u8; 32];

const ALICE_ENCODED: Seed = [
	212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133,
	76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125,
];

pub fn alice_account() -> AccountId {
	sp_core::sr25519::Pair::from_seed(&ALICE_ENCODED).public().into()
}

impl<Executor: IndirectExecutor> IndirectDispatch<Executor> for TransferToAliceShieldsFundsArgs {
	fn dispatch(&self, executor: &Executor) -> Result<()> {
		let alice = alice_account();
		if self.destination == alice {
			info!("Found Transfer to Alice extrinsic in block: \nAmount: {}", self.value);

			let shard = executor.get_default_shard();
			let trusted_call =
				TrustedCall::balance_shield(executor.get_enclave_account()?, alice, self.value);
			let signed_trusted_call = executor.sign_call_with_self(&trusted_call, &shard)?;
			let trusted_operation = TrustedOperation::indirect_call(signed_trusted_call);

			let encrypted_trusted_call = executor.encrypt(&trusted_operation.encode())?;
			executor.submit_trusted_call(shard, encrypted_trusted_call);
		} else {
			log::trace!("Transfer on parentchain was not for alice")
		}

		Ok(())
	}
}
