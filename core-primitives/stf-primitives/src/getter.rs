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

use crate::types::{AccountId, KeyPair, Signature};
use codec::{Decode, Encode};
use ita_sgx_runtime::System;
use itp_stf_interface::ExecuteGetter;
use itp_utils::stringify::account_id_to_string;
use log::*;
use sp_runtime::traits::Verify;
use std::prelude::v1::*;

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Getter<TG = TrustedGetter> {
	public(PublicGetter),
	trusted(TrustedGetterSigned<TG>),
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
}

pub trait TrustedGetterTrait {
	fn sender_account(&self) -> &AccountId;
}

impl TrustedGetter {
	pub fn sign(&self, pair: &KeyPair) -> TrustedGetterSigned {
		let signature = pair.sign(self.encode().as_slice());
		TrustedGetterSigned { getter: self.clone(), signature }
	}
}

impl TrustedGetterTrait for TrustedGetter {
	fn sender_account(&self) -> &AccountId {
		match self {
			TrustedGetter::free_balance(sender_account) => sender_account,
			TrustedGetter::reserved_balance(sender_account) => sender_account,
			TrustedGetter::nonce(sender_account) => sender_account,
		}
	}
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct TrustedGetterSigned<TG = TrustedGetter> {
	pub getter: TG,
	pub signature: Signature,
}

impl<TG> TrustedGetterSigned<TG>
where
	TG: Encode + TrustedGetterTrait,
{
	pub fn new(getter: TG, signature: Signature) -> Self {
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
