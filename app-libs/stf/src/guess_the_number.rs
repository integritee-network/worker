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

// TrustedCalls and Getters for the Guess-The-Number game

use crate::{
	helpers::{shielding_target_genesis_hash, store_note},
	TrustedCall,
};
#[cfg(not(feature = "std"))]
use alloc::format;
use codec::{Decode, Encode};
use frame_support::dispatch::UnfilteredDispatchable;
use ita_parentchain_specs::MinimalChainSpec;
use ita_sgx_runtime::{GuessTheNumber, GuessType, Runtime, System};
use itp_node_api::metadata::provider::AccessNodeMetadata;
use itp_node_api_metadata::NodeMetadataTrait;
use itp_sgx_runtime_primitives::types::{Balance, Moment, ShardIdentifier};
use itp_stf_interface::{ExecuteCall, ExecuteGetter};
use itp_stf_primitives::error::StfError;
use itp_types::{parentchain::ParentchainCall, AccountId};
use itp_utils::stringify::account_id_to_string;
use log::*;
use sp_std::{sync::Arc, vec, vec::Vec};

/// General public information about the status of the guess-the-number game
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct GuessTheNumberInfo {
	/// the account of the pot used to payout winnings
	pub account: itp_stf_primitives::types::AccountId,
	/// the current balance of the pot
	pub balance: Balance,
	/// the amount which can be won every round
	pub winnings: Balance,
	/// the time when this round will end and the next round will start
	pub next_round_timestamp: Moment,
	/// the winners of the previous round
	pub last_winners: Vec<itp_stf_primitives::types::AccountId>,
	/// the lucky number which the enclave picked at random at the beginning of the last round
	pub maybe_last_lucky_number: Option<GuessType>,
	/// the distance of the best guess to the lucky_number
	pub maybe_last_winning_distance: Option<GuessType>,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
#[allow(clippy::unnecessary_cast)]
pub enum GuessTheNumberTrustedCall {
	set_winnings(AccountId, Balance) = 0,
	push_by_one_day(AccountId) = 1,
	guess(AccountId, GuessType) = 2,
}

impl GuessTheNumberTrustedCall {
	pub fn sender_account(&self) -> &AccountId {
		match self {
			Self::set_winnings(sender_account, ..) => sender_account,
			Self::push_by_one_day(sender_account) => sender_account,
			Self::guess(sender_account, ..) => sender_account,
		}
	}
}

impl<NodeMetadataRepository> ExecuteCall<NodeMetadataRepository> for GuessTheNumberTrustedCall
where
	NodeMetadataRepository: AccessNodeMetadata,
	NodeMetadataRepository::MetadataType: NodeMetadataTrait,
{
	type Error = StfError;

	fn execute(
		self,
		_calls: &mut Vec<ParentchainCall>,
		_shard: &ShardIdentifier,
		_node_metadata_repo: Arc<NodeMetadataRepository>,
	) -> Result<(), Self::Error> {
		match self.clone() {
			Self::set_winnings(sender, winnings) => {
				// authorization happens in pallet itself, we just pass authentication
				let origin = ita_sgx_runtime::RuntimeOrigin::signed(sender.clone());
				std::println!("⣿STF⣿ guess-the-number set winnings to {}", winnings);
				ita_sgx_runtime::GuessTheNumberCall::<Runtime>::set_winnings { winnings }
					.dispatch_bypass_filter(origin)
					.map_err(|e| {
						Self::Error::Dispatch(format!(
							"GuessTheNumber Set winnings error: {:?}",
							e.error
						))
					})?;
				store_note(&sender, TrustedCall::guess_the_number(self), vec![sender.clone()])?;
				Ok::<(), Self::Error>(())
			},
			Self::push_by_one_day(sender) => {
				// authorization happens in pallet itself, we just pass authentication
				let origin = ita_sgx_runtime::RuntimeOrigin::signed(sender.clone());
				std::println!("⣿STF⣿ guess-the-number push by one day");
				ita_sgx_runtime::GuessTheNumberCall::<Runtime>::push_by_one_day {}
					.dispatch_bypass_filter(origin)
					.map_err(|e| {
						Self::Error::Dispatch(format!(
							"GuessTheNumber push by one day error: {:?}",
							e.error
						))
					})?;
				store_note(&sender, TrustedCall::guess_the_number(self), vec![sender.clone()])?;
				Ok::<(), Self::Error>(())
			},
			Self::guess(sender, guess) => {
				let origin = ita_sgx_runtime::RuntimeOrigin::signed(sender.clone());
				std::println!("⣿STF⣿ guess-the-number: someone is attempting a guess");
				ita_sgx_runtime::GuessTheNumberCall::<Runtime>::guess { guess }
					.dispatch_bypass_filter(origin)
					.map_err(|e| {
						Self::Error::Dispatch(format!("GuessTheNumber guess error: {:?}", e.error))
					})?;
				store_note(&sender, TrustedCall::guess_the_number(self), vec![sender.clone()])?;
				Ok::<(), Self::Error>(())
			},
		}?;
		Ok(())
	}

	fn get_storage_hashes_to_update(self, _shard: &ShardIdentifier) -> Vec<Vec<u8>> {
		debug!("No storage updates needed...");
		Vec::new()
	}
}

pub fn get_fee_for(tc: &GuessTheNumberTrustedCall) -> Balance {
	let one = MinimalChainSpec::one_unit(shielding_target_genesis_hash().unwrap_or_default());
	match tc {
		GuessTheNumberTrustedCall::guess(..) => one / crate::STF_GUESS_FEE_UNIT_DIVIDER,
		_ => Balance::from(0u32),
	}
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum GuessTheNumberPublicGetter {
	guess_the_number_info = 0,
}

impl ExecuteGetter for GuessTheNumberPublicGetter {
	fn execute(self) -> Option<Vec<u8>> {
		match self {
			Self::guess_the_number_info => {
				let account = GuessTheNumber::get_pot_account();
				let winnings = GuessTheNumber::winnings();
				let next_round_timestamp = GuessTheNumber::next_round_timestamp();
				let maybe_last_winning_distance = GuessTheNumber::last_winning_distance();
				let last_winners = GuessTheNumber::last_winners();
				let maybe_last_lucky_number = GuessTheNumber::last_lucky_number();
				let info = System::account(&account);
				trace!("TrustedGetter GuessTheNumber Pot Info");
				trace!("AccountInfo for pot {} is {:?}", account_id_to_string(&account), info);
				std::println!("⣿STF⣿ 🔍 TrustedGetter query: guess-the-number pot info");
				Some(
					GuessTheNumberInfo {
						account,
						balance: info.data.free,
						winnings,
						next_round_timestamp,
						last_winners,
						maybe_last_lucky_number,
						maybe_last_winning_distance,
					}
					.encode(),
				)
			},
		}
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		Vec::new()
	}
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum GuessTheNumberTrustedGetter {
	attempts { origin: AccountId },
}

impl GuessTheNumberTrustedGetter {
	pub fn sender_account(&self) -> &AccountId {
		match self {
			Self::attempts { origin, .. } => origin,
		}
	}
}

impl ExecuteGetter for GuessTheNumberTrustedGetter {
	fn execute(self) -> Option<Vec<u8>> {
		match self {
			Self::attempts { origin } => Some(GuessTheNumber::guess_attempts(&origin).encode()),
		}
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		Vec::new()
	}
}
