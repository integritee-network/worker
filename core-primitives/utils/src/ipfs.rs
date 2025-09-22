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

use alloc::vec::Vec;
use cid::Cid;
use codec::{Decode, Encode};
use core::{
	convert::TryFrom,
	fmt::{Debug, Display},
};
use ipfs_unixfs::file::adder::FileAdder;
use multibase::Base;

/// IPFS content identifier helper: https://docs.ipfs.tech/concepts/content-addressing/
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

impl IpfsCid {
	pub fn from_content_bytes(content: &Vec<u8>) -> Result<Self, IpfsError> {
		let mut adder: FileAdder = FileAdder::default();
		let mut total: usize = 0;
		let mut stats = Stats::default();
		while total < content.len() {
			let (blocks, consumed) = adder.push(&content[total..]);
			total += consumed;
			stats.process(blocks);
		}
		let blocks = adder.finish();
		stats.process(blocks);
		stats.last.map(IpfsCid).ok_or(IpfsError::FinalCidMissing)
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
		let cid_str = Base::Base58Btc.encode(self.0.hash().as_bytes());
		write!(f, "{}", cid_str)
	}
}

impl Display for IpfsCid {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let cid_str = Base::Base58Btc.encode(self.0.hash().as_bytes());
		write!(f, "{}", cid_str)
	}
}

impl Default for IpfsCid {
	fn default() -> Self {
		IpfsCid::from_content_bytes(&Vec::new()).expect("known to work for empty vec")
	}
}

#[derive(Debug, PartialEq)]
pub enum IpfsError {
	InputCidInvalid,
	FinalCidMissing,
	Verification,
}

/// IPFS chunk blocks helper
/// See https://ipfs-search.readthedocs.io/en/latest/ipfs_datatypes.html#files
#[derive(Default)]
pub struct Stats {
	pub blocks: usize,
	pub block_bytes: u64,
	pub last: Option<Cid>,
}

impl Stats {
	fn process<I: Iterator<Item = (Cid, Vec<u8>)>>(&mut self, new_blocks: I) {
		for (cid, block) in new_blocks {
			self.last = Some(cid);
			self.blocks += 1;
			self.block_bytes += block.len() as u64;
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec;
	#[test]
	pub fn test_from_multichunk_content_works() {
		let expected_cid_str = "QmSaFjwJ2QtS3rZDKzC98XEzv2bqT4TfpWLCpphPPwyQTr";
		let expected_cid = IpfsCid::try_from(expected_cid_str).unwrap();
		let content: Vec<u8> = vec![20; 512 * 1024]; // bigger than one chunk of 256kB
		let derived_cid = IpfsCid::from_content_bytes(&content).unwrap();
		assert_eq!(derived_cid, expected_cid);
	}

	#[test]
	pub fn test_cid_verification_fails_for_incorrect_multichunk_content() {
		let expected_cid_str = "QmSaFjwJ2QtS3rZDKzC98XEzv2bqT4TfpWLCpphPPwyQTr";
		let expected_cid = IpfsCid::try_from(expected_cid_str).unwrap();
		let content: Vec<u8> = vec![99; 512 * 1024]; // bigger than one chunk of 256kB
		let wrong_cid = IpfsCid::from_content_bytes(&content).unwrap();
		assert!(wrong_cid != expected_cid);
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

	#[test]
	pub fn test_default_cid_works() {
		let expected_cid_str = "QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH";
		let expected_cid = IpfsCid::try_from(expected_cid_str).unwrap();
		let def = IpfsCid::default();
		assert_eq!(def, expected_cid);
	}
}
