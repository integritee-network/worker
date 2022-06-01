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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::error::Result;
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;
use sp_core::{blake2_256, ed25519::Pair as Ed25519Pair, Pair};

/// Trait to derive an Ed25519 key pair.
pub trait DeriveEd25519 {
	fn derive_ed25519(&self) -> Result<Ed25519Pair>;
}

impl DeriveEd25519 for Rsa3072KeyPair {
	fn derive_ed25519(&self) -> Result<Ed25519Pair> {
		let encoded_key = serde_json::to_vec(self)?;
		let seed = blake2_256(&encoded_key);
		Ok(Ed25519Pair::from_seed(&seed))
	}
}
