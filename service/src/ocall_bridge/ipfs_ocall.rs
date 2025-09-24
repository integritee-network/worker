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
use chrono::Local;
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient, TryFromUri};
use itp_utils::IpfsCid;
use log::*;
use std::{
	fmt::Display,
	fs::{create_dir_all, File},
	io::{self, Cursor, Write},
	path::{Path, PathBuf},
	str,
	sync::Arc,
};
use tokio::runtime::Runtime;

pub struct IpfsOCall {
	client: Option<Arc<IpfsClient>>,
	log_dir: Arc<Path>,
}

impl IpfsOCall {
	pub fn new(maybe_url: Option<String>, maybe_auth: Option<String>, log_dir: Arc<Path>) -> Self {
		if let Some(url) = maybe_url {
			let client = ipfs_api_backend_hyper::IpfsClient::from_str(&url).unwrap();
			let client = if let Some((user, pwd)) = maybe_auth
				.and_then(|s| s.split_once(':').map(|(u, p)| (u.to_string(), p.to_string())))
			{
				info!("Using IPFS node at {} with credentials ******", url);
				client.with_credentials(user, pwd)
			} else {
				info!("Using IPFS node at {}", url);
				client
			};
			let version = tokio::runtime::Runtime::new().unwrap().block_on(client.version());
			match version {
				Ok(v) => info!("Connected to IPFS node version: {}", v.version),
				Err(e) => error!("Error getting IPFS node version: {}", e),
			}
			Self { client: Some(Arc::new(client)), log_dir }
		} else {
			info!("No IPFS URL provided, disabling IPFS.");
			Self { client: None, log_dir }
		}
	}
}

impl IpfsBridge for IpfsOCall {
	fn write_to_ipfs(&self, data: &'static [u8]) -> OCallBridgeResult<()> {
		trace!("    Entering ocall_write_ipfs to write {}B", data.len());
		if let Some(ref client) = self.client {
			let datac = Cursor::new(data);
			let rt = Runtime::new().unwrap();
			match rt.block_on(client.add(datac)) {
				Ok(res) => {
					debug!("ocall result IpfsCid {}", res.hash);
				},
				Err(e) => {
					let dumpfile = log_failing_blob_to_file(data.into(), self.log_dir.clone())
						.unwrap_or_else(|e| e.to_string().into());
					warn!("      write to ipfs failed late, wrote to file {}", dumpfile.display());
				},
			};
		} else {
			warn!("IPFS client not configured, writing to local file");
			let dumpfile = log_failing_blob_to_file(data.into(), self.log_dir.clone())
				.unwrap_or_else(|e| e.to_string().into());
		};
		Ok(())
	}
}

fn log_failing_blob_to_file(blob: Vec<u8>, log_dir: Arc<Path>) -> io::Result<PathBuf> {
	let log_dir = log_dir.join("log-ipfs-failing-add");
	create_dir_all(&log_dir)?;
	let timestamp = Local::now().format("%Y%m%d-%H%M%S-%3f").to_string();
	let cid_str = IpfsCid::from_content_bytes(&blob)
		.map(|cid| format!("{}", cid))
		.unwrap_or_else(|_| "invalid-cid".to_string());
	let file_name = format!("ipfs-{}-{}.bin", timestamp, cid_str);
	let file_path = log_dir.join(file_name);
	let mut file = File::create(file_path.clone())?;
	file.write_all(&blob)?;
	warn!("      write to ipfs failed early, wrote to file {}", file_path.display());
	Ok(file_path)
}
