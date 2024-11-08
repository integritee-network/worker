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
use ita_sgx_runtime::{
	Balances, Notes, ParentchainIntegritee, ParentchainTargetA, ParentchainTargetB, System,
};
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

use crate::{
	guess_the_number::{GuessTheNumberPublicGetter, GuessTheNumberTrustedGetter},
	helpers::{shielding_target, shielding_target_genesis_hash, wrap_bytes},
};
use ita_parentchain_specs::MinimalChainSpec;
use itp_sgx_runtime_primitives::types::Moment;
use itp_stf_primitives::traits::{GetDecimals, PoolTransactionValidation};
use itp_types::parentchain::{BlockNumber, Hash, ParentchainId};
use pallet_notes::BucketIndex;
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

impl GetDecimals for Getter {
	fn get_shielding_target_decimals() -> u8 {
		MinimalChainSpec::decimals(shielding_target_genesis_hash().unwrap_or_default())
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
#[allow(clippy::unnecessary_cast)]
pub enum PublicGetter {
	some_value = 0,
	total_issuance = 1,
	parentchains_info = 10,
	note_buckets_info = 11,
	guess_the_number(GuessTheNumberPublicGetter) = 50,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
#[allow(clippy::unnecessary_cast)]
pub enum TrustedGetter {
	account_info(AccountId) = 0,
	notes_for(AccountId, BucketIndex) = 10,
	guess_the_number(GuessTheNumberTrustedGetter) = 50,
	#[cfg(feature = "evm")]
	evm_nonce(AccountId) = 90,
	#[cfg(feature = "evm")]
	evm_account_codes(AccountId, H160) = 91,
	#[cfg(feature = "evm")]
	evm_account_storages(AccountId, H160, H256) = 92,
}

impl TrustedGetter {
	pub fn sender_account(&self) -> &AccountId {
		match self {
			TrustedGetter::account_info(sender_account) => sender_account,
			TrustedGetter::notes_for(sender_account, ..) => sender_account,
			TrustedGetter::guess_the_number(getter) => getter.sender_account(),
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
			TrustedGetter::account_info(who) => {
				let info = System::account(&who);
				debug!("TrustedGetter account_data");
				debug!("AccountInfo for {} is {:?}", account_id_to_string(&who), info);
				std::println!("⣿STF⣿ 🔍 TrustedGetter query: account info for ⣿⣿⣿ is ⣿⣿⣿",);
				Some(info.encode())
			},
			TrustedGetter::notes_for(who, bucket_index) => {
				debug!("TrustedGetter notes_for");
				let note_indices = Notes::notes_lookup(bucket_index, &who);
				debug!("Note indices for {} are {:?}", account_id_to_string(&who), note_indices);
				// todo: do we need pagination here?
				let mut notes = Vec::new();
				for note_index in note_indices {
					if let Some(note) = Notes::notes(bucket_index, note_index) {
						notes.push(note)
					};
				}
				std::println!("⣿STF⣿ 🔍 TrustedGetter query: notes for ⣿⣿⣿",);
				Some(notes.encode())
			},
			TrustedGetter::guess_the_number(getter) => getter.execute(),
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
		let mut key_hashes = Vec::new();
		match self.getter {
			TrustedGetter::guess_the_number(getter) =>
				key_hashes.append(&mut getter.get_storage_hashes_to_update()),
			_ => debug!("No storage updates needed..."),
		};
		key_hashes
	}
}

impl ExecuteGetter for PublicGetter {
	fn execute(self) -> Option<Vec<u8>> {
		match self {
			PublicGetter::some_value => Some(42u32.encode()),
			PublicGetter::total_issuance => Some(Balances::total_issuance().encode()),
			PublicGetter::parentchains_info => {
				let integritee = ParentchainInfo {
					id: ParentchainId::Integritee,
					genesis_hash: ParentchainIntegritee::parentchain_genesis_hash(),
					block_number: ParentchainIntegritee::block_number(),
					now: ParentchainIntegritee::now(),
					creation_block_number: ParentchainIntegritee::creation_block_number(),
					creation_timestamp: ParentchainIntegritee::creation_timestamp(),
				};
				let target_a = ParentchainInfo {
					id: ParentchainId::TargetA,
					genesis_hash: ParentchainTargetA::parentchain_genesis_hash(),
					block_number: ParentchainTargetA::block_number(),
					now: ParentchainTargetA::now(),
					creation_block_number: ParentchainTargetA::creation_block_number(),
					creation_timestamp: ParentchainTargetA::creation_timestamp(),
				};
				let target_b = ParentchainInfo {
					id: ParentchainId::TargetB,
					genesis_hash: ParentchainTargetB::parentchain_genesis_hash(),
					block_number: ParentchainTargetB::block_number(),
					now: ParentchainTargetB::now(),
					creation_block_number: ParentchainTargetB::creation_block_number(),
					creation_timestamp: ParentchainTargetB::creation_timestamp(),
				};
				let parentchains_info = ParentchainsInfo {
					integritee,
					target_a,
					target_b,
					shielding_target: shielding_target(),
				};
				Some(parentchains_info.encode())
			},
			PublicGetter::note_buckets_info => {
				let first_bucket = Notes::buckets(0);
				let last_bucket = Notes::buckets(0);
				Some((first_bucket, last_bucket).encode())
			},
			PublicGetter::guess_the_number(getter) => getter.execute(),
		}
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		let mut key_hashes = Vec::new();
		match self {
			Self::guess_the_number(getter) =>
				key_hashes.append(&mut getter.get_storage_hashes_to_update()),
			_ => debug!("No storage updates needed..."),
		};
		key_hashes
	}
}

/// General public information about the sync status of all parentchains
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct ParentchainsInfo {
	/// info for the integritee network parentchain
	pub integritee: ParentchainInfo,
	/// info for the target A parentchain
	pub target_a: ParentchainInfo,
	/// info for the target B parentchain
	pub target_b: ParentchainInfo,
	/// which of the parentchains is used as a shielding target?
	pub shielding_target: ParentchainId,
}

/// General public information about the sync status of a parentchain
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct ParentchainInfo {
	/// the parentchain id for internal use
	id: ParentchainId,
	/// the genesis hash of the parentchain
	genesis_hash: Option<Hash>,
	/// the last imported parentchain block number
	block_number: Option<BlockNumber>,
	/// the timestamp of the last imported parentchain block
	now: Option<Moment>,
	/// the parentchain block number which preceded the creation of this shard
	creation_block_number: Option<BlockNumber>,
	/// the timestamp of creation for this shard
	creation_timestamp: Option<Moment>,
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
