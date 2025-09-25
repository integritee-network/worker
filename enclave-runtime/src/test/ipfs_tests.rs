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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

use crate::ocall::OcallApi;
use itp_ipfs_cid::IpfsCid;
use itp_ocall_api::EnclaveIpfsOCallApi;
use log::*;
use std::{
	fs,
	io::Read,
	path::{Path, PathBuf},
	string::{String, ToString},
	vec::Vec,
};

pub fn test_ocall_write_ipfs_fallback() {
	let payload_size = 100; // in kB
	info!("testing IPFS write of {}kB if api is unreachable. Expected to fallback to dump local file...", payload_size);
	let enc_state: Vec<u8> = vec![20; payload_size * 1024];
	let res_expected_cid = IpfsCid::from_chunk(&enc_state);
	let result = OcallApi.write_ipfs(enc_state);
	debug!("write_ipfs ocall result : {:?}", result);
	debug!("expected cid details: {:?}", res_expected_cid);
	assert!(res_expected_cid.is_ok());
	let expected_cid = res_expected_cid.expect("known to be ok");
	info!("expected cid: {}", expected_cid);
	let dumpfile =
		find_first_matching_file(expected_cid.to_string()).expect("dumped file not found");
	info!("found dumped file: {:?}", dumpfile);
	let mut f = fs::File::open(dumpfile).unwrap();
	let mut content_buf = Vec::new();
	f.read_to_end(&mut content_buf).unwrap();
	debug!("reading file {:?} of size {} bytes", f, &content_buf.len());
	let res_file_cid = IpfsCid::from_chunk(&content_buf);
	debug!("file cid details: {:?}", res_file_cid);
	assert!(res_file_cid.is_ok());
	let file_cid = res_file_cid.expect("known to be ok");
	debug!("file cid: {}", file_cid);
	assert_eq!(expected_cid, file_cid);
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
