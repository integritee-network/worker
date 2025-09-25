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

use log::*;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use sgx_tcrypto::{rsgx_sha256_slice, SgxEccHandle};
#[cfg(not(all(not(feature = "std"), feature = "sgx")))]
use sha2::{Digest, Sha256};
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
use codec::{Decode, Encode};
use multibase::Base;
use multihash::Multihash;
use std::{
	convert::TryFrom,
	fmt::{Debug, Display},
	vec::Vec,
};
const SHA2_256: u64 = 0x12;
const RAW: u64 = 0x55;
#[derive(Clone, PartialEq, Eq)]
pub struct IpfsCid(pub Cid);

impl From<Cid> for IpfsCid {
	fn from(value: Cid) -> Self {
		IpfsCid(value)
	}
}

impl TryFrom<&str> for IpfsCid {
	type Error = cid::Error;

	fn try_from(value: &str) -> Result<Self, Self::Error> {
		let cid = Cid::try_from(value)?;
		Ok(IpfsCid(cid))
	}
}

impl Encode for IpfsCid {
	fn encode(&self) -> Vec<u8> {
		self.0.to_bytes().encode()
	}
}

impl Decode for IpfsCid {
	fn decode<I: codec::Input>(input: &mut I) -> Result<Self, codec::Error> {
		let bytes: Vec<u8> = Decode::decode(input)?;
		let cid = Cid::try_from(bytes)
			.map_err(|_| codec::Error::from("Failed to decode IpfsCid from bytes"))?;
		Ok(IpfsCid(cid))
	}
}

impl Debug for IpfsCid {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let cid = &self.0;
		let version = cid.version();
		let codec = cid.codec();
		let mh = cid.hash();
		let mh_code = mh.code();
		let mh_size = mh.size();
		let mh_digest = mh.digest();

		f.debug_struct("IpfsCid")
			.field("version", &version)
			.field("codec", &codec)
			.field("multihash_code", &mh_code)
			.field("multihash_size", &mh_size)
			.field("multihash_digest", &hex::encode(mh_digest))
			.finish()
	}
}

impl Display for IpfsCid {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let cid_str = if self.0.codec() == RAW {
			multibase::encode(Base::Base32Lower, self.0.to_bytes())
		} else {
			multibase::encode(Base::Base58Btc, self.0.to_bytes())
		};
		write!(f, "{}", cid_str)
	}
}
impl IpfsCid {
	pub fn from_chunk(chunk: &[u8]) -> Result<Self, IpfsError> {
		if chunk.len() > 256 * 1024 {
			return Err(IpfsError::InputTooLarge);
		};
		let hash = hasher(chunk)?;
		info!("hash: {:?}", hash);
		let mh = Multihash::wrap(SHA2_256, &hash).map_err(|_| IpfsError::InputTooLarge)?;
		let cid = Cid::new_v1(RAW, mh);
		info!("cid: {:?}", cid);
		Ok(Self(cid))
	}
}

#[cfg(all(not(feature = "std"), feature = "sgx"))]
// sha2 crashes enclaves. therefore we need to use this SDK-provided hasher for sgx builds
fn hasher(chunk: &[u8]) -> Result<[u8; 32], IpfsError> {
	rsgx_sha256_slice(&chunk).map_err(|_| IpfsError::InputTooLarge)
}
#[cfg(not(all(not(feature = "std"), feature = "sgx")))]
fn hasher(chunk: &[u8]) -> Result<[u8; 32], IpfsError> {
	Ok(Sha256::digest(chunk).into())
}

#[derive(Debug, PartialEq)]
pub enum IpfsError {
	InputTooLarge,
	InputCidInvalid,
	FinalCidMissing,
	Verification,
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::vec;

	#[test]
	pub fn test_from_max_chunk_content_works() {
		// cross-check with ipfs cli:
		// head -c 262144 /dev/zero | tr '\0' 'A' | ipfs block put --format=raw
		// bafkreiexul6fkqo4zhagxgnsvbgdjfq7udb26ig3uoli34xznjlmnpaaze
		let expected_cid_str = "bafkreiexul6fkqo4zhagxgnsvbgdjfq7udb26ig3uoli34xznjlmnpaaze";
		let expected_cid = IpfsCid::try_from(expected_cid_str).unwrap();
		let content: Vec<u8> = vec![65; 256 * 1024]; // exactly one chunk of 256kB of "A" chars
		let derived_cid = IpfsCid::from_chunk(&content).unwrap();
		assert_eq!(derived_cid, expected_cid);
	}

	#[test]
	pub fn test_cid_verification_fails_for_incorrect_single_chunk_content() {
		let expected_cid_str = "bafkreihdcgl5emugcgwjavoknx76kmfdahpzz3jyghg5mhslvhbrznfkky";
		let expected_cid = IpfsCid::try_from(expected_cid_str).unwrap();
		let content: Vec<u8> = vec![99; 256 * 1024];
		let wrong_cid = IpfsCid::from_chunk(&content).unwrap();
		assert!(wrong_cid != expected_cid);
	}
	#[test]
	pub fn test_from_text_works() {
		// cross-check with ipfs cli:
		// echo -n "FooBar" | ipfs block put --format=raw
		// bafkreianosnl4e3xk42jhyg7otpy2euc4ruwo5kkd26hzrrsher2pcfnlq
		let expected_cid_str = "bafkreianosnl4e3xk42jhyg7otpy2euc4ruwo5kkd26hzrrsher2pcfnlq";
		let expected_cid = IpfsCid::try_from(expected_cid_str).unwrap();
		let content = "FooBar".as_bytes();
		let derived_cid = IpfsCid::from_chunk(content).unwrap();
		assert_eq!(derived_cid, expected_cid);
	}

	#[test]
	pub fn test_cid_verification_fails_for_oversize_chunk_content() {
		let content: Vec<u8> = vec![99; 256 * 1024 + 1];
		assert!(IpfsCid::from_chunk(&content) == Err(IpfsError::InputTooLarge));
	}

	#[test]
	pub fn test_encode_decode_ipfscid_works() {
		let expected_cid_str = "QmSaFjwJ2QtS3rZDKzC98XEzv2bqT4TfpWLCpphPPwyQTr";
		let expected_cid = IpfsCid::try_from(expected_cid_str).unwrap();
		let encoded = expected_cid.encode();
		assert_eq!(encoded.len(), 34 + 1);
		let decoded = IpfsCid::decode(&mut &encoded[..]).unwrap();
		assert_eq!(decoded, expected_cid);
	}
}
