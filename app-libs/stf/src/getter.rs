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

use codec::{Decode, Encode};
use ita_sgx_runtime::{Balances, GuessTheNumber, GuessType, System};
use itp_stf_interface::ExecuteGetter;
use itp_stf_primitives::{
	traits::GetterAuthorization,
	types::{AccountId, KeyPair, Signature},
};
use itp_utils::stringify::account_id_to_string;
use log::*;
use sp_runtime::traits::Verify;
use sp_std::vec;
use std::prelude::v1::*;

#[cfg(feature = "evm")]
use ita_sgx_runtime::{AddressMapping, HashedAddressMapping};

#[cfg(feature = "evm")]
use crate::evm_helpers::{get_evm_account, get_evm_account_codes, get_evm_account_storages};

use crate::helpers::wrap_bytes;
use itp_sgx_runtime_primitives::types::{Balance, Moment};
use itp_stf_primitives::traits::PoolTransactionValidation;
#[cfg(feature = "evm")]
use sp_core::{H160, H256};
use sp_runtime::transaction_validity::{
	TransactionValidityError, UnknownTransaction, ValidTransaction,
};

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Getter {
	public(PublicGetter),
	trusted(TrustedGetterSigned),
}

impl Default for Getter {
	fn default() -> Self {
		Getter::public(PublicGetter::some_value)
	}
}
impl From<PublicGetter> for Getter {
	fn from(item: PublicGetter) -> Self {
		Getter::public(item)
	}
}

impl From<TrustedGetterSigned> for Getter {
	fn from(item: TrustedGetterSigned) -> Self {
		Getter::trusted(item)
	}
}

impl GetterAuthorization for Getter {
	fn is_authorized(&self) -> bool {
		match self {
			Self::trusted(ref getter) => getter.verify_signature(),
			Self::public(_) => true,
		}
	}
}

impl PoolTransactionValidation for Getter {
	fn validate(&self) -> Result<ValidTransaction, TransactionValidityError> {
		match self {
			Self::public(_) =>
				Err(TransactionValidityError::Unknown(UnknownTransaction::CannotLookup)),
			Self::trusted(trusted_getter_signed) => Ok(ValidTransaction {
				priority: 1 << 20,
				requires: vec![],
				provides: vec![trusted_getter_signed.signature.encode()],
				longevity: 64,
				propagate: true,
			}),
		}
	}
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum PublicGetter {
	some_value = 0u8,
	total_issuance = 1u8,
	guess_the_number_last_lucky_number = 50u8,
	guess_the_number_last_winning_distance = 51u8,
	guess_the_number_info = 52u8,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum TrustedGetter {
	free_balance(AccountId) = 0u8,
	reserved_balance(AccountId) = 1u8,
	nonce(AccountId) = 2u8,
	#[cfg(feature = "evm")]
	evm_nonce(AccountId) = 80u8,
	#[cfg(feature = "evm")]
	evm_account_codes(AccountId, H160) = 81u8,
	#[cfg(feature = "evm")]
	evm_account_storages(AccountId, H160, H256) = 82u8,
}

impl TrustedGetter {
	pub fn sender_account(&self) -> &AccountId {
		match self {
			TrustedGetter::free_balance(sender_account) => sender_account,
			TrustedGetter::reserved_balance(sender_account) => sender_account,
			TrustedGetter::nonce(sender_account) => sender_account,
			#[cfg(feature = "evm")]
			TrustedGetter::evm_nonce(sender_account) => sender_account,
			#[cfg(feature = "evm")]
			TrustedGetter::evm_account_codes(sender_account, _) => sender_account,
			#[cfg(feature = "evm")]
			TrustedGetter::evm_account_storages(sender_account, ..) => sender_account,
		}
	}

	pub fn sign(&self, pair: &KeyPair) -> TrustedGetterSigned {
		let signature = pair.sign(self.encode().as_slice());
		TrustedGetterSigned { getter: self.clone(), signature }
	}
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct TrustedGetterSigned {
	pub getter: TrustedGetter,
	pub signature: Signature,
}

impl TrustedGetterSigned {
	pub fn new(getter: TrustedGetter, signature: Signature) -> Self {
		TrustedGetterSigned { getter, signature }
	}

	pub fn verify_signature(&self) -> bool {
		let encoded = self.getter.encode();

		if self.signature.verify(encoded.as_slice(), self.getter.sender_account()) {
			return true
		};

		// check if the signature is from an extension-dapp signer.
		self.signature
			.verify(wrap_bytes(&encoded).as_slice(), self.getter.sender_account())
	}
}

impl ExecuteGetter for Getter {
	fn execute(self) -> Option<Vec<u8>> {
		match self {
			Getter::trusted(g) => g.execute(),
			Getter::public(g) => g.execute(),
		}
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		match self {
			Getter::trusted(g) => g.get_storage_hashes_to_update(),
			Getter::public(g) => g.get_storage_hashes_to_update(),
		}
	}
}

impl ExecuteGetter for TrustedGetterSigned {
	fn execute(self) -> Option<Vec<u8>> {
		match self.getter {
			TrustedGetter::free_balance(who) => {
				let info = System::account(&who);
				debug!("TrustedGetter free_balance");
				debug!("AccountInfo for {} is {:?}", account_id_to_string(&who), info);
				std::println!("⣿STF⣿ 🔍 TrustedGetter query: free balance for ⣿⣿⣿ is ⣿⣿⣿",);
				Some(info.data.free.encode())
			},
			TrustedGetter::reserved_balance(who) => {
				let info = System::account(&who);
				debug!("TrustedGetter reserved_balance");
				debug!("AccountInfo for {} is {:?}", account_id_to_string(&who), info);
				debug!("Account reserved balance is {}", info.data.reserved);
				Some(info.data.reserved.encode())
			},
			TrustedGetter::nonce(who) => {
				let nonce = System::account_nonce(&who);
				debug!("TrustedGetter nonce");
				debug!("Account nonce is {}", nonce);
				Some(nonce.encode())
			},
			#[cfg(feature = "evm")]
			TrustedGetter::evm_nonce(who) => {
				let evm_account = get_evm_account(&who);
				let evm_account = HashedAddressMapping::into_account_id(evm_account);
				let nonce = System::account_nonce(&evm_account);
				debug!("TrustedGetter evm_nonce");
				debug!("Account nonce is {}", nonce);
				Some(nonce.encode())
			},
			#[cfg(feature = "evm")]
			TrustedGetter::evm_account_codes(_who, evm_account) =>
			// TODO: This probably needs some security check if who == evm_account (or assosciated)
				if let Some(info) = get_evm_account_codes(&evm_account) {
					debug!("TrustedGetter Evm Account Codes");
					debug!("AccountCodes for {} is {:?}", evm_account, info);
					Some(info) // TOOD: encoded?
				} else {
					None
				},
			#[cfg(feature = "evm")]
			TrustedGetter::evm_account_storages(_who, evm_account, index) =>
			// TODO: This probably needs some security check if who == evm_account (or assosciated)
				if let Some(value) = get_evm_account_storages(&evm_account, &index) {
					debug!("TrustedGetter Evm Account Storages");
					debug!("AccountStorages for {} is {:?}", evm_account, value);
					Some(value.encode())
				} else {
					None
				},
		}
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		Vec::new()
	}
}

impl ExecuteGetter for PublicGetter {
	fn execute(self) -> Option<Vec<u8>> {
		match self {
			PublicGetter::some_value => Some(42u32.encode()),
			PublicGetter::total_issuance => Some(Balances::total_issuance().encode()),
			PublicGetter::guess_the_number_last_lucky_number => {
				// todo! return suiting value, not this one
				GuessTheNumber::lucky_number().map(|guess| guess.encode())
			},
			PublicGetter::guess_the_number_last_winning_distance => {
				// todo! return suiting value, not this one
				GuessTheNumber::lucky_number().map(|guess| guess.encode())
			},
			PublicGetter::guess_the_number_info => {
				let account = GuessTheNumber::get_pot_account();
				let winnings = GuessTheNumber::winnings();
				let next_round_timestamp = GuessTheNumber::next_round_timestamp();
				let maybe_last_winning_distance = GuessTheNumber::last_winning_distance();
				let last_winners = GuessTheNumber::last_winners();
				let maybe_last_lucky_number = GuessTheNumber::last_lucky_number();
				let info = System::account(&account);
				debug!("TrustedGetter GuessTheNumber Pot Info");
				debug!("AccountInfo for pot {} is {:?}", account_id_to_string(&account), info);
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
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct GuessTheNumberInfo {
	pub account: AccountId,
	pub balance: Balance,
	pub winnings: Balance,
	pub next_round_timestamp: Moment,
	pub last_winners: Vec<AccountId>,
	pub maybe_last_lucky_number: Option<GuessType>,
	pub maybe_last_winning_distance: Option<GuessType>,
}

mod tests {
	use super::*;

	#[test]
	fn extension_dapp_signature_works() {
		// This is a getter, which has been signed in the browser with the `signRaw` interface,
		// which wraps the data in `<Bytes>...</Bytes>`
		//
		// see: https://github.com/polkadot-js/extension/pull/743
		let dapp_extension_signed_getter: Vec<u8> = vec![
			1, 0, 6, 72, 250, 19, 15, 144, 30, 85, 114, 224, 117, 219, 65, 218, 30, 241, 136, 74,
			157, 10, 202, 233, 233, 100, 255, 63, 64, 102, 81, 215, 65, 60, 1, 192, 224, 67, 233,
			49, 104, 156, 159, 245, 26, 136, 60, 88, 123, 174, 171, 67, 215, 124, 223, 112, 16,
			133, 35, 138, 241, 36, 68, 27, 41, 63, 14, 103, 132, 201, 130, 216, 43, 81, 123, 71,
			149, 215, 191, 100, 58, 182, 123, 229, 188, 245, 130, 66, 202, 126, 51, 137, 140, 56,
			44, 176, 239, 51, 131,
		];
		let getter = Getter::decode(&mut dapp_extension_signed_getter.as_slice()).unwrap();

		if let Getter::trusted(trusted) = getter {
			let g = &trusted.getter;
			let signature = &trusted.signature;

			// check the signature check itself works
			assert!(signature.verify(wrap_bytes(&g.encode()).as_slice(), g.sender_account()));

			// check that the trusted getter's method works
			assert!(trusted.verify_signature())
		} else {
			panic!("invalid getter")
		}
	}
}
