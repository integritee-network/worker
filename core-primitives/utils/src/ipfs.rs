use alloc::vec::Vec;
use cid::Cid;
use codec::{Decode, Encode};
use core::{convert::TryFrom, fmt::Debug};
use ipfs_unixfs::file::adder::FileAdder;
use multibase::Base;

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
		stats.last.map(|cid| IpfsCid(cid)).ok_or(IpfsError::FinalCidMissing)
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

pub struct IpfsContent {
	pub cid: IpfsCid,
	pub file_content: Vec<u8>,
}
#[derive(Debug, PartialEq)]
pub enum IpfsError {
	InputCidInvalid,
	FinalCidMissing,
	Verification,
}

impl IpfsContent {
	pub fn new_with_cid_unverified(cid: IpfsCid, content: Vec<u8>) -> IpfsContent {
		IpfsContent { cid, file_content: content }
	}

	pub fn verify(&mut self) -> Result<(), IpfsError> {
		let derived_cid = Self::derive_cid_from_file_content(&self.file_content)?;
		if derived_cid.0.hash().eq(&self.cid.0.hash()) {
			Ok(())
		} else {
			Err(IpfsError::Verification)
		}
	}

	pub fn derive_cid_from_file_content(file_content: &Vec<u8>) -> Result<IpfsCid, IpfsError> {
		let mut adder: FileAdder = FileAdder::default();
		let mut total: usize = 0;
		let mut stats = Stats::default();
		while total < file_content.len() {
			let (blocks, consumed) = adder.push(&file_content[total..]);
			total += consumed;
			stats.process(blocks);
		}
		let blocks = adder.finish();
		stats.process(blocks);
		stats.last.map(|cid| IpfsCid(cid)).ok_or(IpfsError::FinalCidMissing)
	}
}

impl TryFrom<Vec<u8>> for IpfsContent {
	type Error = IpfsError;

	fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
		let cid = Self::derive_cid_from_file_content(&value)?;
		Ok(IpfsContent { cid, file_content: value })
	}
}

impl Debug for IpfsContent {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let cid_str = Base::Base58Btc.encode(self.cid.0.hash().as_bytes());
		f.debug_struct("IpfsContent")
			.field("cid", &cid_str)
			.field("file_content_length", &self.file_content.len())
			.finish()
	}
}

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
	pub fn test_try_from_multichunk_content_works() {
		let expected_cid_str = "QmSaFjwJ2QtS3rZDKzC98XEzv2bqT4TfpWLCpphPPwyQTr";
		let expected_cid = IpfsCid::try_from(expected_cid_str).unwrap();
		let content: Vec<u8> = vec![20; 512 * 1024]; // bigger than one chunk of 256kB
		let ipfs_content = IpfsContent::try_from(content.clone()).unwrap();
		assert_eq!(ipfs_content.cid, expected_cid);
		assert_eq!(ipfs_content.file_content, content);
	}

	#[test]
	pub fn test_verification_ok_for_correct_multichunk_content() {
		let expected_cid_str = "QmSaFjwJ2QtS3rZDKzC98XEzv2bqT4TfpWLCpphPPwyQTr";
		let expected_cid = IpfsCid::try_from(expected_cid_str).unwrap();
		let content: Vec<u8> = vec![20; 512 * 1024]; // bigger than one chunk of 256kB
		let mut ipfs_content = IpfsContent::new_with_cid_unverified(expected_cid, content);
		let verification = ipfs_content.verify();
		assert!(verification.is_ok());
	}

	#[test]
	pub fn test_verification_fails_for_incorrect_multichunk_content() {
		let expected_cid_str = "QmSaFjwJ2QtS3rZDKzC98XEzv2bqT4TfpWLCpphPPwyQTr";
		let expected_cid = IpfsCid::try_from(expected_cid_str).unwrap();
		let content: Vec<u8> = vec![99; 512 * 1024]; // bigger than one chunk of 256kB
		let mut ipfs_content = IpfsContent::new_with_cid_unverified(expected_cid, content);
		let verification = ipfs_content.verify();
		assert!(verification.is_err());
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
