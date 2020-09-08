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

use std::fs::File;
use std::io::{Cursor, Write};
use std::slice;
use std::str;
use std::sync::mpsc::channel;

use sgx_types::*;

use futures::TryStreamExt;
use ipfs_api::IpfsClient;
use log::*;

pub type Cid = [u8; 46];

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
        }
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

#[no_mangle]
pub unsafe extern "C" fn ocall_write_ipfs(
    enc_state: *const u8,
    enc_state_size: u32,
    cid: *mut u8,
    cid_size: u32,
) -> sgx_status_t {
    debug!("    Entering ocall_write_ipfs");

    let state = slice::from_raw_parts(enc_state, enc_state_size as usize);
    let cid = slice::from_raw_parts_mut(cid, cid_size as usize);

    let _cid = write_to_ipfs(state);
    cid.clone_from_slice(&_cid);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ocall_read_ipfs(cid: *const u8, cid_size: u32) -> sgx_status_t {
    debug!("Entering ocall_read_ipfs");

    let _cid = slice::from_raw_parts(cid, cid_size as usize);

    let mut cid = [0; 46];
    cid.clone_from_slice(_cid);

    let result = read_from_ipfs(cid);
    match result {
        Ok(res) => {
            let filename = str::from_utf8(&cid).unwrap();
            match File::create(filename) {
                Ok(mut f) => f.write_all(&res).map_or_else(
                    |e| {
                        error!("ocall_read_ipfs failed writing to file. {}", e);
                        sgx_status_t::SGX_ERROR_UNEXPECTED
                    },
                    |_| sgx_status_t::SGX_SUCCESS,
                ),
                Err(e) => {
                    error!("ocall_read_ipfs failed at creating file. {}", e);
                    sgx_status_t::SGX_ERROR_UNEXPECTED
                }
            }
        }
        Err(_) => sgx_status_t::SGX_ERROR_UNEXPECTED,
    }
}
