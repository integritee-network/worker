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

use codec::Encode;
pub use ita_sgx_runtime::{Balance, Index};

use ita_stf::{Getter, TrustedCall, TrustedCallSigned};
use itc_parentchain_indirect_calls_executor::error::Error;
use itp_stf_primitives::{traits::IndirectExecutor, types::TrustedOperation};
use itp_types::parentchain::{AccountId, FilterEvents, HandleParentchainEvents, ParentchainError};
use itp_utils::hex::hex_encode;
use log::*;

pub struct ParentchainEventHandler {}

impl ParentchainEventHandler {
	fn shield_funds<Executor: IndirectExecutor<TrustedCallSigned, Error>>(
		executor: &Executor,
		account: &AccountId,
		amount: Balance,
	) -> Result<(), Error> {
		trace!("[TargetA] shielding for {:?} amount {}", account, amount,);
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
	fn handle_events(
		executor: &Executor,
		events: impl FilterEvents,
		vault_account: &AccountId,
	) -> Result<(), Error> {
		let filter_events = events.get_transfer_events();
		trace!(
			"[TargetA] filtering transfer events to shard vault account: {}",
			hex_encode(vault_account.encode().as_slice())
		);
		if let Ok(events) = filter_events {
			events
				.iter()
				.filter(|&event| event.to == *vault_account)
				.try_for_each(|event| {
					std::println!("⣿TargetA⣿ 🛡 found transfer event to shard vault account: {} will shield to {}", event.amount, hex_encode(event.from.encode().as_ref()));
					Self::shield_funds(executor, &event.from, event.amount)
				})
				.map_err(|_| ParentchainError::ShieldFundsFailure)?;
		}
		Ok(())
	}
}
