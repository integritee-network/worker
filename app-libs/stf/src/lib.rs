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

/////////////////////////////////////////////////////////////////////////////
#![feature(structural_match)]
#![feature(rustc_attrs)]
#![feature(core_intrinsics)]
#![feature(derive_eq)]
#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

#[cfg(feature = "sgx")]
pub use ita_sgx_runtime::{Balance, Index};
#[cfg(feature = "std")]
pub use my_node_runtime::{Balance, Index};

use codec::{Decode, Encode};
use derive_more::Display;
use std::string::String;

use crate::types::AccountId;

pub use getter::*;
pub use stf_sgx_primitives::{types::*, Stf};
pub use trusted_call::*;

#[cfg(feature = "evm")]
pub mod evm_helpers;
pub mod getter;
pub mod hash;
pub mod helpers;
pub mod stf_sgx;
pub mod stf_sgx_primitives;
#[cfg(all(feature = "test", feature = "sgx"))]
pub mod stf_sgx_tests;
#[cfg(all(feature = "test", feature = "sgx"))]
pub mod test_genesis;
pub mod trusted_call;

pub(crate) const ENCLAVE_ACCOUNT_KEY: &str = "Enclave_Account_Key";

pub mod types {
	use sp_core::ed25519;

	use sp_core::Pair;

	use sp_core::sr25519;

	use std::boxed::Box;

	use codec::Compact;

	use sp_core::H256;

	use sp_core::crypto::AccountId32;

	use sp_runtime::traits::Verify;

	use sp_runtime::MultiSignature;

	pub type Signature = MultiSignature;

	pub type AuthorityId = <Signature as Verify>::Signer;

	pub type AccountId = AccountId32;

	pub type Hash = H256;

	pub type BalanceTransferFn = ([u8; 2], AccountId, Compact<u128>);

	pub type ShardIdentifier = H256;

	#[derive(Clone)]
	pub enum KeyPair {
		Sr25519(Box<sr25519::Pair>),
		Ed25519(Box<ed25519::Pair>),
	}

	impl KeyPair {
		pub(crate) fn sign(&self, payload: &[u8]) -> Signature {
			match self {
				Self::Sr25519(pair) => pair.sign(payload).into(),
				Self::Ed25519(pair) => pair.sign(payload).into(),
			}
		}
	}

	impl From<ed25519::Pair> for KeyPair {
		fn from(x: ed25519::Pair) -> Self {
			KeyPair::Ed25519(Box::new(x))
		}
	}

	impl From<sr25519::Pair> for KeyPair {
		fn from(x: sr25519::Pair) -> Self {
			KeyPair::Sr25519(Box::new(x))
		}
	}
}

pub type StfResult<T> = Result<T, StfError>;

#[derive(Debug, Display, PartialEq, Eq)]
pub enum StfError {
	#[display(fmt = "Insufficient privileges {:?}, are you sure you are root?", _0)]
	MissingPrivileges(AccountId),
	#[display(fmt = "Valid enclave signer account is required")]
	RequireEnclaveSignerAccount,
	#[display(fmt = "Error dispatching runtime call. {:?}", _0)]
	Dispatch(String),
	#[display(fmt = "Not enough funds to perform operation")]
	MissingFunds,
	#[display(fmt = "Invalid Nonce {:?}", _0)]
	InvalidNonce(Index),
	StorageHashMismatch,
	InvalidStorageDiff,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TrustedOperation {
	indirect_call(TrustedCallSigned),
	direct_call(TrustedCallSigned),
	get(Getter),
}

impl From<TrustedCallSigned> for TrustedOperation {
	fn from(item: TrustedCallSigned) -> Self {
		TrustedOperation::indirect_call(item)
	}
}

impl From<Getter> for TrustedOperation {
	fn from(item: Getter) -> Self {
		TrustedOperation::get(item)
	}
}

impl From<TrustedGetterSigned> for TrustedOperation {
	fn from(item: TrustedGetterSigned) -> Self {
		TrustedOperation::get(item.into())
	}
}

impl From<PublicGetter> for TrustedOperation {
	fn from(item: PublicGetter) -> Self {
		TrustedOperation::get(item.into())
	}
}

impl TrustedOperation {
	pub fn to_call(&self) -> Option<&TrustedCallSigned> {
		match self {
			TrustedOperation::direct_call(c) => Some(c),
			TrustedOperation::indirect_call(c) => Some(c),
			_ => None,
		}
	}
}
