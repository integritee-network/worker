use cid::{Cid, Result as CidResult};
use ipfs_unixfs::file::adder::FileAdder;
use log::*;
use multibase::Base;
use std::{convert::TryFrom, vec::Vec};

pub struct IpfsContent {
	pub cid: CidResult<Cid>,
	pub file_content: Vec<u8>,
	pub stats: Stats,
}
#[derive(Debug, PartialEq)]
pub enum IpfsError {
	InputCidInvalid,
	FinalCidMissing,
	Verification,
}

impl IpfsContent {
	pub fn new(_cid: &str, _content: Vec<u8>) -> IpfsContent {
		IpfsContent { cid: Cid::try_from(_cid), file_content: _content, stats: Stats::default() }
	}

	pub fn verify(&mut self) -> Result<(), IpfsError> {
		let mut adder: FileAdder = FileAdder::default();
		let mut total: usize = 0;
		while total < self.file_content.len() {
			let (blocks, consumed) = adder.push(&self.file_content[total..]);
			total += consumed;
			self.stats.process(blocks);
		}
		let blocks = adder.finish();
		self.stats.process(blocks);

		if let Some(last_cid) = self.stats.last.as_ref() {
			let cid_str = Base::Base58Btc.encode(last_cid.hash().as_bytes());
			info!(
				"new cid: {} generated from {} blocks, total of {} bytes",
				cid_str, self.stats.blocks, self.stats.block_bytes
			);
			match self.cid.as_ref() {
				Ok(initial_cid) =>
					if last_cid.hash().eq(&initial_cid.hash()) {
						Ok(())
					} else {
						Err(IpfsError::Verification)
					},
				Err(_) => Err(IpfsError::InputCidInvalid),
			}
		} else {
			Err(IpfsError::FinalCidMissing)
		}
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

#[allow(unused)]
pub fn test_creates_ipfs_content_struct_works() {
	let cid = "QmSaFjwJ2QtS3rZDKzC98XEzv2bqT4TfpWLCpphPPwyQTr";
	let content: Vec<u8> = vec![20; 512 * 1024];
	let ipfs_content = IpfsContent::new(cid, content.clone());

	let cid_str = Base::Base58Btc.encode(ipfs_content.cid.as_ref().unwrap().hash().as_bytes());
	assert_eq!(cid_str, cid);
	assert_eq!(ipfs_content.file_content, content);
}

#[allow(unused)]
pub fn test_verification_ok_for_correct_content() {
	let cid = "QmSaFjwJ2QtS3rZDKzC98XEzv2bqT4TfpWLCpphPPwyQTr";
	let content: Vec<u8> = vec![20; 512 * 1024];
	let mut ipfs_content = IpfsContent::new(cid, content);
	let verification = ipfs_content.verify();
	assert!(verification.is_ok());
}

#[allow(unused)]
pub fn test_verification_fails_for_incorrect_content() {
	let cid = "QmSaFjwJ2QtS3rZDKzC98XEzv2bqT4TfpWLCpphPPwyQTr";
	let content: Vec<u8> = vec![10; 512 * 1024];
	let mut ipfs_content = IpfsContent::new(cid, content);
	let verification = ipfs_content.verify();
	assert_eq!(verification.unwrap_err(), IpfsError::Verification);
}
