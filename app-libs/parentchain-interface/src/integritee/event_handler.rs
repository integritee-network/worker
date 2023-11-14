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

use codec::{Encode};


pub use ita_sgx_runtime::{Balance, Index};
use ita_sgx_runtime::{System};
use ita_stf::{Getter, TrustedCall, TrustedCallSigned};
use itc_parentchain_indirect_calls_executor::error::Error;
use itp_stf_primitives::{
	traits::{IndirectExecutor},
	types::TrustedOperation,
};
use itp_types::parentchain::{AccountId, FilterEvents, HandleParentchainEvents, ParentchainError};
use log::*;

type Seed = [u8; 32];

const ALICE_ENCODED: Seed = [
	212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133,
	76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125,
];

const SHIELDING_ACCOUNT: AccountId = AccountId::new(ALICE_ENCODED);

pub struct ParentchainEventHandler {}

impl ParentchainEventHandler {
	fn shield_funds<Executor: IndirectExecutor<TrustedCallSigned, Error>>(
		executor: &Executor,
		account: &AccountId,
		amount: Balance,
	) -> Result<(), Error> {
		let account_info = System::account(&account);
		log::info!(
			"shielding for {:?} amount {} new_free {} new_reserved {}",
			account,
			amount,
			account_info.data.free + amount,
			account_info.data.reserved
		);
		let shard = executor.get_default_shard();
		let trusted_call =
			TrustedCall::balance_shield(executor.get_enclave_account()?, account.clone(), amount);
		let signed_trusted_call = executor.sign_call_with_self(&trusted_call, &shard)?;
		let trusted_operation =
			TrustedOperation::<TrustedCallSigned, Getter>::indirect_call(signed_trusted_call);

		let encrypted_trusted_call = executor.encrypt(&trusted_operation.encode())?;
		executor.submit_trusted_call(shard, encrypted_trusted_call);

		Ok(())
	}
}

impl<Executor> HandleParentchainEvents<Executor, TrustedCallSigned, Error>
	for ParentchainEventHandler
where
	Executor: IndirectExecutor<TrustedCallSigned, Error>,
{
	fn handle_events(executor: &Executor, events: impl FilterEvents) -> Result<(), Error> {
		let filter_events = events.get_transfer_events();

		if let Ok(events) = filter_events {
			events
				.iter()
				.filter(|&event| event.to == SHIELDING_ACCOUNT)
				.try_for_each(|event| {
					info!("transfer_event: {}", event);
					//call = IndirectCall::ShieldFunds(ShieldFundsArgs{ })
					Self::shield_funds(executor, &event.from, event.amount)
				})
				.map_err(|_| ParentchainError::ShieldFundsFailure)?;
		}
		Ok(())
	}
}
