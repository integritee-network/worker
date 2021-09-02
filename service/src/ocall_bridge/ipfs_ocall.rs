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

use crate::ocall_bridge::bridge_api::{Cid, IpfsBridge, OCallBridgeError, OCallBridgeResult};
use futures::TryStreamExt;
use ipfs_api::IpfsClient;
use log::*;
use std::{
	fs::File,
	io::{Cursor, Write},
	str,
	sync::mpsc::channel,
};

pub struct IpfsOCall;

impl IpfsBridge for IpfsOCall {
	fn write_to_ipfs(&self, data: &'static [u8]) -> OCallBridgeResult<Cid> {
		debug!("    Entering ocall_write_ipfs");
		Ok(write_to_ipfs(data))
	}

	fn read_from_ipfs(&self, cid: Cid) -> OCallBridgeResult<()> {
		debug!("Entering ocall_read_ipfs");

		let result = read_from_ipfs(cid);
		match result {
			Ok(res) => {
				let filename = str::from_utf8(&cid).unwrap();
				create_file(filename, &res).map_err(OCallBridgeError::IpfsError)
			},
			Err(_) => Err(OCallBridgeError::IpfsError("failed to read from IPFS".to_string())),
		}
	}
}

fn create_file(filename: &str, result: &[u8]) -> Result<(), String> {
	match File::create(filename) {
		Ok(mut f) => f
			.write_all(result)
			.map_or_else(|e| Err(format!("failed writing to file: {}", e)), |_| Ok(())),
		Err(e) => Err(format!("failed to create file: {}", e)),
	}
}

#[tokio::main]
async fn write_to_ipfs(data: &'static [u8]) -> Cid {
	// Creates an `IpfsClient` connected to the endpoint specified in ~/.ipfs/api.
	// If not found, tries to connect to `localhost:5001`.
	let client = IpfsClient::default();

	match client.version().await {
		Ok(version) => info!("version: {:?}", version.version),
		Err(e) => eprintln!("error getting version: {}", e),
	}

	let datac = Cursor::new(data);
	let (tx, rx) = channel();

	match client.add(datac).await {
		Ok(res) => {
			info!("Result Hash {}", res.hash);
			tx.send(res.hash.into_bytes()).unwrap();
		},
		Err(e) => eprintln!("error adding file: {}", e),
	}
	let mut cid: Cid = [0; 46];
	cid.clone_from_slice(&rx.recv().unwrap());
	cid
}

#[tokio::main]
pub async fn read_from_ipfs(cid: Cid) -> Result<Vec<u8>, String> {
	// Creates an `IpfsClient` connected to the endpoint specified in ~/.ipfs/api.
	// If not found, tries to connect to `localhost:5001`.
	let client = IpfsClient::default();
	let h = str::from_utf8(&cid).unwrap();

	info!("Fetching content from: {}", h);

	client
		.cat(h)
		.map_ok(|chunk| chunk.to_vec())
		.map_err(|e| e.to_string())
		.try_concat()
		.await
}
