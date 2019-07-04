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

use cid::{Cid, Codec, Prefix, Version};
use futures::Future;
use ipfs_api::IpfsClient;
use log::*;
use multihash::{decode, encode, Hash, Multihash, to_hex};
use rust_base58::{FromBase58, ToBase58};
use sgx_types::*;
use sha2::{Digest, Sha256};
use std::io::{self, Cursor, Write};
use std::slice;
use std::str;

fn write_to_ipfs(data: &'static [u8]) -> Cid {
	println!("connecting to localhost:5001...");
	let client = IpfsClient::default();

	let req = client
		.version()
		.map(|version| println!("version: {:?}", version.version));

	hyper::rt::run(req.map_err(|e| eprintln!("{}", e)));

	println!("Data {:?}", data);
	let datac = Cursor::new(data);

	let req = client
		.add(datac)
		.map(|res| {
			println!("Result Hash {}", res.hash);
			println!("Result Hash {:?}", res.hash.as_bytes());

//			let addrmh = decode(&res.hash.as_bytes()).unwrap();
//			let hash = addrmh.digest;
//			println!("digest: {}", str::from_utf8(hash).unwrap());
//			println!("digest: {:?}", to_hex(hash));
		})
		.map_err(|e| eprintln!("{}", e));

	hyper::rt::run(req);

	/*
    let req = client
        .get("QmNYERzV2LfD2kkfahtfv44ocHzEFK1sLBaE7zdcYT2GAZ")
        .concat2()
        .map(|res| {
            let out = io::stdout();
            let mut out = out.lock();
            out.write_all(&res).unwrap();
        })
        .map_err(|e| eprintln!("{}", e));
    hyper::rt::run(req);
    */

	let h = multihash::encode(multihash::Hash::SHA2256, data).unwrap();
	println!("MultiHash: {:?}", h);

	let cid = Cid::new(Codec::Raw, Version::V1, &h);
	let prefix = cid.prefix();

	let cid2 = Cid::new_from_prefix(&prefix, data);

	/*
    address created like this with ipfs client (echo adds a "\n"!)
        > echo awesome test content > test.txt
        > ipfs add --raw-leaves test.txt
        zb2rhgCbaGmTcdZVRpZi3Z8CsdtAbFv7PRdRD9s6mKtef6LK9
    */

	let prefix_bytes = prefix.as_bytes();
	let prefix2 = Prefix::new_from_bytes(&prefix_bytes).unwrap();

	println!("cid1: {:?} codec:  prefix: {:x?}", cid.to_string(), prefix.as_bytes());
	println!("cid2: {} codec:  prefix: {:x?}", cid2.to_string(), prefix2.as_bytes());

	cid
}

#[no_mangle]
pub unsafe extern "C" fn ocall_write_ipfs(enc_state: *const u8,
										  enc_state_size: u32,
										  cid: *mut u8,
										  cid_size: u32) -> sgx_status_t {
	let state = slice::from_raw_parts(enc_state, enc_state_size as usize);
	let cid = slice::from_raw_parts_mut(cid, cid_size as usize);

	println!("    Entering ocall_write_ipfs");

	let _cid = write_to_ipfs(state);
	cid.clone_from_slice(_cid.to_bytes().as_slice());
	sgx_status_t::SGX_SUCCESS
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn ipfs_works() {
		let data = b"awesome test content\n";
		write_to_ipfs(data.as_slice());
	}
}
