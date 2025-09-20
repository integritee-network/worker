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
    client: Option<Arc<IpfsClient>>,
}

impl IpfsOCall {
    pub fn new(maybe_url: Option<String>, maybe_auth: Option<String>) -> Self {
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
            Self { client: Some(Arc::new(client)) }
        } else {
            info!("No IPFS URL provided, disabling IPFS.");
            Self { client: None }
        }
    }
}

impl IpfsBridge for IpfsOCall {
    fn write_to_ipfs(&self, data: &'static [u8]) -> OCallBridgeResult<IpfsCid> {
        debug!("    Entering ocall_write_ipfs");
        write_to_ipfs(
            self.client.as_ref().ok_or_else(||
                OCallBridgeError::IpfsError("No IPFS client configured, cannot write to IPFS".to_string())
            )?,
            data,
        )
    }

    fn read_from_ipfs(&self, cid: IpfsCid) -> OCallBridgeResult<()> {
        debug!("Entering ocall_read_ipfs");
        let client = self.client.as_ref().ok_or_else(||
            OCallBridgeError::IpfsError("No IPFS client configured, cannot read from IPFS".to_string())
        )?;
        let res = read_from_ipfs(client, &cid)
            .map_err(|_| OCallBridgeError::IpfsError("failed to read from IPFS".to_string()))?;
        let filename = format!("{:?}", cid);
        create_file(&filename, &res).map_err(OCallBridgeError::IpfsError)
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
        }
        Err(e) => {
            error!("error adding file: {}", e);
            return Err(OCallBridgeError::IpfsError(format!("error adding file: {}", e)));
        }
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
