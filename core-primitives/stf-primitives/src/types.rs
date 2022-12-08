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
extern crate alloc;
use alloc::boxed::Box;
use codec::Compact;
use sp_core::{crypto::AccountId32, ed25519, sr25519, Pair, H256};
use sp_runtime::{traits::Verify, MultiSignature};

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
	pub fn sign(&self, payload: &[u8]) -> Signature {
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
