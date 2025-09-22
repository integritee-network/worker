/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

use crate::ocall::OcallApi;
use codec::Decode;
use itp_ocall_api::EnclaveIpfsOCallApi;
use itp_utils::IpfsCid;
use log::*;
use std::{
	fs,
	io::Read,
	path::{Path, PathBuf},
	string::{String, ToString},
	vec::Vec,
};

#[allow(unused)]
/// this test neeeds an ipfs node running and configured with cli args. here for reference but may never be called
pub fn test_ocall_read_write_ipfs() {
	println!("testing IPFS read/write. Hopefully ipfs daemon is running...");
	let enc_state: Vec<u8> = vec![20; 4 * 512 * 1024];

	let expected_cid = IpfsCid::from_content_bytes(&enc_state).unwrap();

	let returned_cid_raw = OcallApi.write_ipfs(enc_state.as_slice()).unwrap();
	let returned_cid = IpfsCid::decode(&mut returned_cid_raw.as_slice()).unwrap();
	assert_eq!(expected_cid, returned_cid);

	OcallApi.read_ipfs(&returned_cid).unwrap();

	let cid_str = format!("{:?}", returned_cid);
	let mut f = fs::File::open(cid_str).unwrap();
	let mut content_buf = Vec::new();
	f.read_to_end(&mut content_buf).unwrap();
	info!("reading file {:?} of size {} bytes", f, &content_buf.len());

	let file_cid = IpfsCid::from_content_bytes(&content_buf).unwrap();
	assert_eq!(expected_cid, file_cid);
}

pub fn test_ocall_write_ipfs_fallback() {
	let payload_sizes = vec![1, 100, 1024];
	for payload_size in payload_sizes {
		println!("testing IPFS write of {}kB if api is unreachable. Expected to fallback to dump local file...", payload_size);
		let enc_state: Vec<u8> = vec![20; payload_size * 1024];
		let expected_cid = IpfsCid::from_content_bytes(&enc_state).unwrap();
		let result = OcallApi.write_ipfs(enc_state.as_slice());

		if result.is_ok() {
			panic!("write_ipfs succeeded, but was expected to fail and fallback to local file dump. Did you accidentally provide an ipfs api url to the test?");
		} else {
			let dumpfile =
				find_first_matching_file(expected_cid.to_string()).expect("dumped file not found");
			let mut f = fs::File::open(dumpfile).unwrap();
			let mut content_buf = Vec::new();
			f.read_to_end(&mut content_buf).unwrap();
			info!("reading file {:?} of size {} bytes", f, &content_buf.len());
			let file_cid = IpfsCid::from_content_bytes(&content_buf).unwrap();
			assert_eq!(expected_cid, file_cid);
		}
	}
}

fn find_first_matching_file(cid_str: String) -> Option<PathBuf> {
	let dir = Path::new("log-ipfs-failing-add");
	let prefix = "ipfs-";
	let suffix = format!("-{}.bin", cid_str);

	for entry in fs::read_dir(dir).ok()? {
		let entry = entry.ok()?;
		let file_name = entry.file_name();
		debug!("Checking file: {:?}", file_name);
		let file_name = file_name.to_string_lossy();
		if file_name.starts_with(prefix) && file_name.ends_with(suffix.as_str()) {
			return Some(entry.path())
		}
	}
	None
}
