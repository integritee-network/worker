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
use multihash::{decode, encode, Hash, Multihash, to_hex};
use rust_base58::{FromBase58, ToBase58};
use sha2::{Digest, Sha256};
use std::io::{self, Cursor, Write};
use std::str;

fn write_to_ipfs() {
	println!("connecting to localhost:5001...");
	let client = IpfsClient::default();

	let req = client
		.version()
		.map(|version| println!("version: {:?}", version.version));

	hyper::rt::run(req.map_err(|e| eprintln!("{}", e)));

	// write data to ipfs
	let data = b"awesome test content\n";
	//let msg = b"Hello World!";
	let datac = Cursor::new(data);
	println!("{:?}", data);


	let req = client
		.add(datac)
		.map(|res| {
			println!("{}", res.hash);

			//let addrmh = decode(res.hash.as_bytes()).unwrap();
			//let hash = addrmh.digest;
			//println!("digest: {}", str::from_utf8(hash).unwrap())
			//println!("digest: {:?}", to_hex(hash))
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

	// test cid

	let h = multihash::encode(multihash::Hash::SHA2256, data).unwrap();

	let cid = Cid::new(Codec::Raw, Version::V1, &h);
	let prefix = cid.prefix();

	let cid2 = Cid::new_from_prefix(&prefix, data);

	/*
    address created like this with ipfs client (echo adds a "\n"!)
        > echo awesome test content > test.txt
        > ipfs add --raw-leaves test.txt
        zb2rhgCbaGmTcdZVRpZi3Z8CsdtAbFv7PRdRD9s6mKtef6LK9
    */

	let cid3 = Cid::from("zb2rhgCbaGmTcdZVRpZi3Z8CsdtAbFv7PRdRD9s6mKtef6LK9").unwrap();

	let prefix_bytes = prefix.as_bytes();
	let prefix2 = Prefix::new_from_bytes(&prefix_bytes).unwrap();


	println!("cid1: {} codec:  prefix: {:x?}", cid.to_string(), prefix.as_bytes());
	println!("cid2: {} codec:  prefix: {:x?}", cid2.to_string(), prefix2.as_bytes());
	println!("cid3: {} codec:  prefix: {:x?}", cid3.to_string(), cid3.prefix().as_bytes());
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn ipfs_works() {
		write_to_ipfs();
	}
}
