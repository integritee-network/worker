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
use ita_sgx_runtime::System;
#[cfg(feature = "evm")]
use ita_sgx_runtime::{AddressMapping, HashedAddressMapping};
use itp_stf_interface::ExecuteGetter;
use itp_stf_primitives::types::{AccountId, KeyPair, Signature};
use itp_utils::stringify::account_id_to_string;
use log::*;
use simplyr_lib::{
	custom_fair_matching, pay_as_bid_matching, GridFeeMatrix, MarketInput, MarketOutput, Order,
	OrderType,
};
use sp_runtime::traits::Verify;
use std::{fs, prelude::v1::*, vec};

#[cfg(feature = "evm")]
use crate::evm_helpers::{get_evm_account, get_evm_account_codes, get_evm_account_storages};

#[cfg(feature = "evm")]
use sp_core::{H160, H256};

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Getter {
	public(PublicGetter),
	trusted(TrustedGetterSigned),
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

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum PublicGetter {
	some_value,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TrustedGetter {
	free_balance(AccountId),
	reserved_balance(AccountId),
	nonce(AccountId),
	#[cfg(feature = "evm")]
	evm_nonce(AccountId),
	#[cfg(feature = "evm")]
	evm_account_codes(AccountId, H160),
	#[cfg(feature = "evm")]
	evm_account_storages(AccountId, H160, H256),
	pay_as_bid(AccountId, FilePath),
	custom_fair(AccountId),
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
			TrustedGetter::pay_as_bid(sender_account, file_path) => sender_account,
			TrustedGetter::custom_fair(sender_account) => sender_account,
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
		self.signature
			.verify(self.getter.encode().as_slice(), self.getter.sender_account())
	}
}

impl ExecuteGetter for Getter {
	fn execute(self) -> Option<Vec<u8>> {
		match self {
			Getter::trusted(g) => match &g.getter {
				TrustedGetter::free_balance(who) => {
					let info = System::account(&who);
					debug!("TrustedGetter free_balance");
					debug!("AccountInfo for {} is {:?}", account_id_to_string(&who), info);
					debug!("Account free balance is {}", info.data.free);
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
					let evm_account = get_evm_account(who);
					let evm_account = HashedAddressMapping::into_account_id(evm_account);
					let nonce = System::account_nonce(&evm_account);
					debug!("TrustedGetter evm_nonce");
					debug!("Account nonce is {}", nonce);
					Some(nonce.encode())
				},
				#[cfg(feature = "evm")]
				TrustedGetter::evm_account_codes(_who, evm_account) =>
				// TODO: This probably needs some security check if who == evm_account (or assosciated)
					if let Some(info) = get_evm_account_codes(evm_account) {
						debug!("TrustedGetter Evm Account Codes");
						debug!("AccountCodes for {} is {:?}", evm_account, info);
						Some(info) // TOOD: encoded?
					} else {
						None
					},
				#[cfg(feature = "evm")]
				TrustedGetter::evm_account_storages(_who, evm_account, index) =>
				// TODO: This probably needs some security check if who == evm_account (or assosciated)
					if let Some(value) = get_evm_account_storages(evm_account, index) {
						debug!("TrustedGetter Evm Account Storages");
						debug!("AccountStorages for {} is {:?}", evm_account, value);
						Some(value.encode())
					} else {
						None
					},

				TrustedGetter::pay_as_bid(_who, file_path) => {
					let content = fs::read_to_string(file_path).expect("error reading file");
					let orders: Vec<Order> =
						serde_json::from_str(&content).expect("error serializing to JSON");

					// create a market input
					let market_input = MarketInput { orders };

					let pay_as_bid: MarketOutput = pay_as_bid_matching(&market_input);
					Some(pay_as_bid.encode())
				},

				TrustedGetter::custom_fair(_who) => {
					// custom_fair_matching
					let order_1 = Order {
						id: 1,
						order_type: OrderType::Ask,
						time_slot: "2022-03-04T05:06:07+00:00".to_string(),
						actor_id: "actor_1".to_string(),
						cluster_index: Some(0),
						energy_kwh: 2.0,
						price_euro_per_kwh: 0.3,
					};

					let order_2 = Order {
						id: 2,
						order_type: OrderType::Bid,
						time_slot: "2022-03-04T05:06:07+00:00".to_string(),
						actor_id: "actor_2".to_string(),
						cluster_index: Some(0),
						energy_kwh: 1.5,
						price_euro_per_kwh: 0.35,
					};

					let grid_fee_matrix =
						GridFeeMatrix::from_json_str("[[0,1,1], [1,0,1], [1,1,0]]").unwrap();

					let market_input = MarketInput { orders: vec![order_1, order_2] };

					let custom_fair: MarketOutput =
						custom_fair_matching(&market_input, 1.0, &grid_fee_matrix);

					Some(custom_fair.encode())
				},
			},
			Getter::public(g) => match g {
				PublicGetter::some_value => Some(42u32.encode()),
			},
		}
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		Vec::new()
	}
}
