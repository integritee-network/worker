use cid::{Cid, Result};
use ipfs_unixfs::file::adder::FileAdder;
use multibase::Base;
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
use std::vec::Vec;

pub struct IpfsContent {
    pub cid: Result<Cid>,
    pub file_content: Vec<u8>,
    pub stats: Stats,
    pub verified: bool,
}

impl IpfsContent {
    pub fn new(_cid: Vec<u8>) -> IpfsContent {
        let cid = std::str::from_utf8(&_cid).unwrap();
        let mut f = File::open(cid).unwrap();
        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer).unwrap();

        println!("reading file {:?} of size {} bytes", f, &buffer.len());

        IpfsContent {
            cid: Cid::try_from(cid),
            file_content: buffer,
            stats: Stats::default(),
            verified: false,
        }
    }

    pub fn verify(&mut self) {
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
            println!(
                "new cid: {} generated from {} blocks, total of {} bytes",
                cid_str, self.stats.blocks, self.stats.block_bytes
            );
            if let Some(initial_cid) = self.cid.as_ref().ok() {
                self.verified = last_cid.hash().eq(&initial_cid.hash());
            }
        } else {
            self.verified = false
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
