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

use crate::{TrustedCall, TrustedOperation};
use codec::Encode;
use frame_support::traits::UnfilteredDispatchable;
pub use ita_sgx_runtime::{Balance, Index};
use ita_sgx_runtime::{Runtime, System};
use itc_parentchain_indirect_calls_executor::traits::IndirectExecutor;
use itp_types::parentchain::{AccountId, FilterEvents, HandleParentchainEvents, ParentchainError};
use log::*;
use sp_runtime::MultiAddress;

type Seed = [u8; 32];

const ALICE_ENCODED: Seed = [
	212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133,
	76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125,
];

pub struct ParentchainEventHandler;

impl HandleParentchainEvents for ParentchainEventHandler {
	const SHIELDING_ACCOUNT: AccountId = AccountId::new(ALICE_ENCODED);

	fn handle_events<Executor: IndirectExecutor>(
		executor: &Executor,
		events: impl FilterEvents,
	) -> Result<(), ParentchainError> {
		let filter_events = events.get_transfer_events();

		if let Ok(events) = filter_events {
			events
				.iter()
				.filter(|&event| event.to == Self::SHIELDING_ACCOUNT)
				.try_for_each(|event| {
					info!("transfer_event: {}", event);
					call = IndirectCall::ShieldFunds(ShieldFundsArgs{ })
					Self::shield_funds(executor, &event.from, event.amount)
				})
				.map_err(|_| ParentchainError::ShieldFundsFailure)?;
		}

		Ok(())
	}

	fn shield_funds<Executor: IndirectExecutor>(
		executor: &Executor,
		account: &AccountId,
		amount: Balance,
	) -> Result<(), ParentchainError> {
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
			TrustedCall::balance_shield(executor.get_enclave_account()?, account, amount);
		let signed_trusted_call = executor.sign_call_with_self(&trusted_call, &shard)?;
		let trusted_operation = TrustedOperation::indirect_call(signed_trusted_call);

		let encrypted_trusted_call = executor.encrypt(&trusted_operation.encode())?;
		executor.submit_trusted_call(shard, encrypted_trusted_call);

		Ok(())
	}
}
