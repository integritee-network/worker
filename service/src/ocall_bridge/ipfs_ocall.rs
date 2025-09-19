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

use crate::ocall_bridge::bridge_api::{IpfsBridge, OCallBridgeError, OCallBridgeResult};
use futures::TryStreamExt;
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient, TryFromUri};
use itp_utils::IpfsCid;
use log::*;
use std::{
	fs::File,
	io::{Cursor, Write},
	str,
	sync::{mpsc::channel, Arc},
};

pub struct IpfsOCall {
	client: Arc<IpfsClient>,
}

impl IpfsOCall {
	pub fn new(client: Option<Arc<IpfsClient>>) -> Self {
		// Fallback if None:
		//   Creates an `IpfsClient` connected to the endpoint specified in ~/.ipfs/api.
		//   If not found, tries to connect to `localhost:5001`.
		Self { client: client.unwrap_or_default() }
	}
}

impl IpfsBridge for IpfsOCall {
	fn write_to_ipfs(&self, data: &'static [u8]) -> OCallBridgeResult<IpfsCid> {
		debug!("    Entering ocall_write_ipfs");
		write_to_ipfs(&self.client, data)
	}

	fn read_from_ipfs(&self, cid: IpfsCid) -> OCallBridgeResult<()> {
		debug!("Entering ocall_read_ipfs");

		let result = read_from_ipfs(&self.client, &cid);
		match result {
			Ok(res) => {
				let filename = format!("{:?}", cid);
				create_file(&filename, &res).map_err(OCallBridgeError::IpfsError)
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
async fn write_to_ipfs(client: &IpfsClient, data: &'static [u8]) -> OCallBridgeResult<IpfsCid> {
	let datac = Cursor::new(data);
	let (tx, rx) = channel();

	match client.add(datac).await {
		Ok(res) => {
			debug!("Result IpfsCid {}", res.hash);
			tx.send(res.hash.into_bytes()).unwrap();
		},
		Err(e) => {
			error!("error adding file: {}", e);
			return Err(OCallBridgeError::IpfsError(format!("error adding file: {}", e)));
		},
	}
	rx.recv()
		.map_err(|e| OCallBridgeError::IpfsError(format!("error receiving cid: {}", e)))
		.and_then(|cid_str| {
			str::from_utf8(&cid_str)
				.map_err(|e| OCallBridgeError::IpfsError(format!("invalid UTF-8 in cid: {}", e)))
				.and_then(|cid_utf8| {
					IpfsCid::try_from(cid_utf8).map_err(|e| {
						OCallBridgeError::IpfsError(format!("invalid IpfsCid: {:?}", e))
					})
				})
		})
}

#[tokio::main]
pub async fn read_from_ipfs(client: &IpfsClient, cid: &IpfsCid) -> Result<Vec<u8>, String> {
	let h = format!("{:?}", cid);
	debug!("Fetching content with cid {}", h);
	client
		.cat(&h)
		.map_ok(|chunk| chunk.to_vec())
		.map_err(|e| e.to_string())
		.try_concat()
		.await
}
