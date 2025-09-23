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
use futures::TryStreamExt;
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient, TryFromUri};
use itp_utils::IpfsCid;
use log::*;
use std::{
	fmt::Display,
	fs::{create_dir_all, File},
	io::{self, Cursor, Write},
	path::{Path, PathBuf},
	str,
	sync::{mpsc::channel, Arc},
};

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
	fn write_to_ipfs(&self, data: &'static [u8]) -> OCallBridgeResult<IpfsCid> {
		eprintln!("    Entering ocall_write_ipfs to write {}B", data.len());
		let result = write_to_ipfs_sync(
            self.client.as_ref().ok_or_else(|| {
                let dumpfile = log_failing_blob_to_file(data.into(), self.log_dir.clone()).unwrap_or_else(|e| e.to_string().into());
                eprintln!("      write to ipfs failed, wrote to file {}", dumpfile.display());
                OCallBridgeError::IpfsError(
                    format!("No IPFS client configured, cannot write to IPFS. Dumped content to local file instead: {}", dumpfile.display())
                )
            })?,
            data,
            self.log_dir.clone(),
        );
		eprintln!("     ipfs result {:?}", result);
		Ok(IpfsCid::default())
	}

	fn read_from_ipfs(&self, cid: IpfsCid) -> OCallBridgeResult<()> {
		eprintln!("     Entering ocall_read_ipfs");
		Ok(())
		// let client = self.client.as_ref().ok_or_else(|| {
		//     OCallBridgeError::IpfsError(
		//         "No IPFS client configured, cannot read from IPFS".to_string(),
		//     )
		// })?;
		// let res = read_from_ipfs(client, &cid)
		//     .map_err(|_| OCallBridgeError::IpfsError("failed to read from IPFS".to_string()))?;
		// let filename = format!("{:?}", cid);
		// create_file(&filename, &res).map_err(OCallBridgeError::IpfsError)
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

use tokio::runtime::Runtime;

fn write_to_ipfs_sync(
	client: &IpfsClient,
	data: &'static [u8],
	log_dir: Arc<Path>,
) -> OCallBridgeResult<IpfsCid> {
	Ok(IpfsCid::default())
	// let datac = Cursor::new(data);
	// let rt = Runtime::new().unwrap();
	//
	// match rt.block_on(client.add(datac)) {
	// 	Ok(res) => {
	// 		eprintln!("ocall result IpfsCid {}", res.hash);
	// 		IpfsCid::try_from(res.hash.as_str())
	// 			.map_err(|e| OCallBridgeError::IpfsError(format!("invalid IpfsCid: {:?}", e)))
	// 	},
	// 	Err(e) => {
	// 		let dumpfile = log_failing_blob_to_file(data.into(), log_dir.clone())
	// 			.unwrap_or_else(|e| e.to_string().into());
	// 		eprintln!("      write to ipfs failed late, wrote to file {}", dumpfile.display());
	// 		Err(OCallBridgeError::IpfsError(format!(
	// 			"error adding file to IPFS: {}. Dumped content to local file instead: {}",
	// 			e,
	// 			dumpfile.display()
	// 		)))
	// 	},
	// }
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
	Ok(file_path)
}
