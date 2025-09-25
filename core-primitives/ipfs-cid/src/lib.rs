/*
	Copyright 2021 Integritee AG

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

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use core::fmt::Debug;
use log::*;
use sgx_tcrypto::{rsgx_sha256_slice, SgxEccHandle};
// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use base64_sgx as base64;
	pub use chrono_sgx as chrono;
	pub use rustls_sgx as rustls;
	pub use serde_json_sgx as serde_json;
	pub use thiserror_sgx as thiserror;
	pub use webpki_sgx as webpki;
	pub use yasna_sgx as yasna;
}
use cid::Cid;
use multihash::Multihash;
const SHA2_256: u64 = 0x12;
const RAW: u64 = 0x55;
#[derive(Clone, PartialEq, Eq)]
pub struct IpfsCid {
	hash: [u8; 32],
}

impl IpfsCid {
	pub fn from_chunk(chunk: &[u8]) -> Result<Self, IpfsError> {
		if chunk.len() > 256 * 1024 {
			return Err(IpfsError::InputTooLarge);
		};
		let hash = rsgx_sha256_slice(&chunk).map_err(|_| IpfsError::InputTooLarge)?;
		info!("hash: {:?}", hash);
		let mh = Multihash::wrap(SHA2_256, &hash).map_err(|_| IpfsError::InputTooLarge)?;
		let cid = Cid::new_v1(RAW, mh);
		info!("cid: {:?}", cid);
		Ok(Self { hash })
	}
}

impl Debug for IpfsCid {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "IpfsCid: hash: {} ", hex::encode(self.hash))
	}
}

#[derive(Debug, PartialEq)]
pub enum IpfsError {
	InputTooLarge,
	InputCidInvalid,
	FinalCidMissing,
	Verification,
}
