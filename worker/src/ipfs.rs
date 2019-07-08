/*
	Copyright 2019 Supercomputing Systems AG

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

use futures::Future;
use ipfs_api::IpfsClient;
use log::*;
use sgx_types::*;
use std::io::Cursor;
use std::slice;
use std::sync::mpsc::channel;
use std::str;
use futures::Stream;

fn write_to_ipfs(data: &'static [u8]) -> [u8; 46] {
	println!("IPFS: \n...connecting to localhost:5001...");
	let client = IpfsClient::default();

	let req = client
		.version()
		.map(|version| println!("version: {:?}", version.version));

	hyper::rt::run(req.map_err(|e| eprintln!("{}", e)));

	let datac = Cursor::new(data);
	let (tx, rx) = channel();

	let req = client
		.add(datac)
		.map(move |res| {
			info!("Result Hash {}", res.hash);
			tx.send(res.hash.into_bytes()).unwrap();
		})
		.map_err(|e| eprintln!("{}", e));

	hyper::rt::run(req);

	let mut cid: [u8; 46] = [0; 46];
	cid.clone_from_slice(&rx.recv().unwrap());
	cid
}

fn read_from_ipfs(cid: [u8; 46]) -> Vec<u8> {
	let client = IpfsClient::default();
	let h = str::from_utf8(&cid).unwrap();

	info!("Fetching content from: {}", h);

	let (tx, rx) = channel();

	let req = client
		.cat(h)
		.concat2()
		.map(move |res| {
			tx.send(res).unwrap();
		})
		.map_err(|e| eprintln!("{}", e));
	hyper::rt::run(req);
	rx.recv().unwrap().to_vec()
}

#[no_mangle]
pub unsafe extern "C" fn ocall_write_ipfs(enc_state: *const u8,
										  enc_state_size: u32,
										  cid: *mut u8,
										  cid_size: u32) -> sgx_status_t {
	debug!("    Entering ocall_write_ipfs");

	let state = slice::from_raw_parts(enc_state, enc_state_size as usize);
	let cid = slice::from_raw_parts_mut(cid, cid_size as usize);

	let _cid = write_to_ipfs(state);
	cid.clone_from_slice(&_cid);
	sgx_status_t::SGX_SUCCESS
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn ipfs_works() {
		let data = b"awesome test content\n";
		let cid = write_to_ipfs(data);
		println!("Returned cid: {:?}", cid.to_vec());
		let res =  read_from_ipfs(cid);
		assert_eq!(data.to_vec(), res)
	}
}
