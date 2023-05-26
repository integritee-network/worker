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

//! All the different crypto schemes that we use in sgx

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use serde_json_sgx as serde_json;
	pub use serde_sgx as serde;
}

pub mod aes;
pub mod ed25519;
pub mod ed25519_derivation;
pub mod error;
pub mod key_repository;
pub mod rsa3072;
pub mod traits;

pub use self::{aes::*, ed25519::*, rsa3072::*};
pub use error::*;
pub use traits::*;

#[cfg(feature = "mocks")]
pub mod mocks;

#[cfg(feature = "test")]
pub mod tests {
	pub use super::ed25519::sgx_tests::{
		ed25529_sealing_works, using_get_ed25519_repository_twice_initializes_key_only_once,
	};

	pub use super::rsa3072::sgx_tests::{
		rsa3072_sealing_works, using_get_rsa3072_repository_twice_initializes_key_only_once,
	};

	pub use super::aes::sgx_tests::{
		aes_sealing_works, using_get_aes_repository_twice_initializes_key_only_once,
	};
}
