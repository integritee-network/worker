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

use crate::StfError;
use frame_support::traits::UnfilteredDispatchable;
pub use ita_sgx_runtime::{Balance, Index};
use ita_sgx_runtime::{Runtime, System};
use itc_parentchain::FilterEvents;
use itp_types::types::{AccountId, ParentchainEventHandler, HandleParentchainEvents, ParentchainError};
use sp_runtime::MultiAddress;
use std::format;

type Seed = [u8; 32];

const ALICE_ENCODED: Seed = [
	212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133,
	76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125,
];

impl HandleParentchainEvents for ParentchainEventHandler {
	const SHIELDING_ACCOUNT: AccountId = AccountId::new(ALICE_ENCODED);

	fn handle_events(events: impl FilterEvents) -> Result<(), ParentchainError> {
		let filter_events = events.get_transfer_events();

		if let Ok(events) = filter_events {
			events
				.iter()
				.filter(|&event| event.to == Self::SHIELDING_ACCOUNT)
				.try_for_each(|event| {
					info!("transfer_event: {}", event);
					Self::shield_funds(&event.from, event.amount)
				}).map_err(|e| ParentchainError::ShieldFundsFailure)?;
		}

		Ok(())
	}

	fn shield_funds(account: &AccountId, amount: Balance) -> Result<(), ParentchainError> {
		let account_info = System::account(&account);
		log::info!(
			"shielding for {:?} amount {} new_free {} new_reserved {}",
			account,
			amount,
			account_info.data.free + amount,
			account_info.data.reserved
		);
		ita_sgx_runtime::BalancesCall::<Runtime>::force_set_balance {
			who: MultiAddress::Id(account.clone()),
			new_free: account_info.data.free + amount,
		}
		.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
		.map_err(|e| ParentchainError::ShieldFundsFailure)?;

		Ok(())
	}
}

impl Display for BalanceTransfer {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		let message = format!(
			"BalanceTransfer :: from: {}, to: {}, amount: {}",
			account_id_to_string::<AccountId>(&self.from),
			account_id_to_string::<AccountId>(&self.to),
			self.amount
		);
		write!(f, "{}", message)
	}
}
