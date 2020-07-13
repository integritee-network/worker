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

use std::io::Cursor;
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
        },
        Err(e) => eprintln!("error adding file: {}", e)
    }
    let mut cid: Cid = [0; 46];
    cid.clone_from_slice(&rx.recv().unwrap());
    cid
}

#[tokio::main]
pub async fn read_from_ipfs(cid: Cid) -> Vec<u8> {
    // Creates an `IpfsClient` connected to the endpoint specified in ~/.ipfs/api.
    // If not found, tries to connect to `localhost:5001`.
    let client = IpfsClient::default();
    let h = str::from_utf8(&cid).unwrap();

    info!("Fetching content from: {}", h);

    let (tx, rx) = channel();

    match client.cat(h)
        .map_ok(|chunk| chunk.to_vec())
        .try_concat()
		.await
		{
            Ok(res) => { tx.send(res).unwrap(); },
            Err(e) => eprintln!("error reading file: {}", e)
        }

    rx.recv().unwrap().to_vec()
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
pub unsafe extern "C" fn ocall_read_ipfs(
    enc_state: *mut u8,
    enc_state_size: u32,
    cid: *const u8,
    cid_size: u32,
) -> sgx_status_t {
    debug!("Entering ocall_read_ipfs");

    let state = slice::from_raw_parts_mut(enc_state, enc_state_size as usize);
    let _cid = slice::from_raw_parts(cid, cid_size as usize);

    let mut cid = [0; 46];
    cid.clone_from_slice(_cid);

    let res = read_from_ipfs(cid);
    state.clone_from_slice(&res);

    sgx_status_t::SGX_SUCCESS
}
