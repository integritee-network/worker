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
use itp_ocall_api::EnclaveIpfsOCallApi;
use itp_utils::IpfsCid;
use log::*;
use std::{fs::File, io::Read, vec::Vec};

#[allow(unused)]
/// this test neeeds an ipfs node running and configured with cli args. here for reference but may never be called
pub fn test_ocall_read_write_ipfs() {
	info!("testing IPFS read/write. Hopefully ipfs daemon is running...");
	let enc_state: Vec<u8> = vec![20; 4 * 512 * 1024];

	let expected_cid = IpfsCid::from_content_bytes(&enc_state).unwrap();

	let returned_cid = OcallApi.write_ipfs(enc_state.as_slice()).unwrap();
	assert_eq!(expected_cid, returned_cid);

	OcallApi.read_ipfs(&returned_cid).unwrap();

	let cid_str = format!("{:?}", returned_cid);
	let mut f = File::open(cid_str).unwrap();
	let mut content_buf = Vec::new();
	f.read_to_end(&mut content_buf).unwrap();
	info!("reading file {:?} of size {} bytes", f, &content_buf.len());

	let file_cid = IpfsCid::from_content_bytes(&content_buf).unwrap();
	assert_eq!(expected_cid, file_cid);
}
