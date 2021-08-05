/*
	Copyright 2019 Supercomputing Systems AG
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

use crate::{
	ipfs::IpfsContent,
	ocall::ocall_component_factory::{OCallComponentFactory, OCallComponentFactoryTrait},
};
use log::*;
use std::{fs::File, io::Read, vec::Vec};
use substratee_ocall_api::EnclaveIpfsOCallApi;

#[allow(unused)]
fn test_ocall_read_write_ipfs() {
	info!("testing IPFS read/write. Hopefully ipfs daemon is running...");
	let enc_state: Vec<u8> = vec![20; 4 * 512 * 1024];

	let ipfs_api = OCallComponentFactory::ipfs_api();

	let cid = ipfs_api.write_ipfs(enc_state.as_slice()).unwrap();

	ipfs_api.read_ipfs(&cid).unwrap();

	let cid_str = std::str::from_utf8(&cid.0).unwrap();
	let mut f = File::open(&cid_str).unwrap();
	let mut content_buf = Vec::new();
	f.read_to_end(&mut content_buf).unwrap();
	info!("reading file {:?} of size {} bytes", f, &content_buf.len());

	let mut ipfs_content = IpfsContent::new(cid_str, content_buf);
	let verification = ipfs_content.verify();
	assert!(verification.is_ok());
}
