#[cfg(not(target_env = "sgx"))]
#[macro_use]
use sgx_tstd as std;
use std::io::Read;
use std::fs::File;
use std::vec::Vec;


pub struct IpfsContent {
	cid: Vec<u8>,
	content: Vec<u8>
}

impl IpfsContent {
	pub fn new (_cid: Vec<u8>) -> IpfsContent {
		let filename =  std::str::from_utf8(&_cid).unwrap();
		let mut f = File::open(filename).unwrap();
		let mut buffer = Vec::new();
		f.read_to_end(&mut buffer).unwrap();
		println!("file {:?}", f);
		IpfsContent {
			cid: _cid,
			content: buffer
		}
	}

	pub fn verify (&self) -> bool {
		true
	}
}
