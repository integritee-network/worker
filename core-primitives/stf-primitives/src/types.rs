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

use derive_more::Display;
use sp_application_crypto::Pair;
use sp_core::{crypto::AccountId32, ed25519, sr25519, H256};
use sp_runtime::MultiSignature;
use std::{boxed::Box, string::String};

use crate::trusted_call::Index;
pub use itp_types::{AccountData, AccountInfo, BlockNumber, Header as ParentchainHeader};
pub type State = itp_sgx_externalities::SgxExternalities;

pub type AccountId = AccountId32;

pub type Signature = MultiSignature;

pub type ShardIdentifier = H256;

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
