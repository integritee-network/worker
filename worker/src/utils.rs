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

use log::*;
use std::path::Path;
use constants::*;
use std::process::Command;
use my_node_runtime::Hash;
use primitive_types::{H256};
use substratee_node_calls::{get_worker_amount, get_latest_state, get_worker_info, Enclave};
use std::sync::mpsc::channel;
use std::thread;
use ws_server::{MSG_MU_RA_PORT, WsClient};
use ws::connect;

pub fn check_files() -> u8 {
	debug!("*** Check files");

	let mut missing_files = 0;
	missing_files += file_missing(ENCLAVE_FILE);
	missing_files += file_missing(RSA_PUB_KEY);
	missing_files += file_missing(ECC_PUB_KEY);

	// remote attestation files
	missing_files += file_missing(RA_SPID);
	missing_files += file_missing(RA_API_KEY);

	missing_files
}

fn file_missing(path: &str) -> u8 {
	if Path::new(path).exists() {
		debug!("File '{}' found", path);
		0
	} else {
		error!("File '{}' not found", path);
		1
	}
}

pub fn get_wasm_hash() -> Vec<String> {
	let sha_cmd = Command::new("sha256sum")
		.arg("worker_enclave.compact.wasm")
		.output()
		.expect("Failed to get sha256sum of worker_enclave.wasm");

	std::str::from_utf8(&sha_cmd.stdout).unwrap()
		.split("  ")
		.map(|s| s.to_string())
		.collect()
}

pub fn get_first_worker_that_is_not_equal_to_self(api: &substrate_api_client::Api, pubkey: Vec<u8>) -> Result<Enclave, &str> {
	let w_amount = get_worker_amount(api);
	let key = vec_to_h256(pubkey);

	match w_amount {
		0 => error!("No worker registered. Can't get worker info from node!"),
		_ => {
			for i in 0 .. w_amount {
				let enc = get_worker_info(api, i);
				if key != enc.pubkey {
					info!("[+] Found worker to fetch keys from!");
					return Ok(enc);
				}
			}
		}
	}
	Err("No worker not equal to self found")
}

pub fn get_mu_ra_port_from_worker(w_url: String) -> Result<String, ()>{

	let (port_in, port_out) = channel();
	let client = thread::spawn(move || {
		match connect(format!("ws://{}",  w_url), |out| {
			WsClient {
				out: out,
				request: MSG_MU_RA_PORT.to_string(),
				result: port_in.clone()
			}
		}) {
			Ok(c) => c,
			Err(_) => {
				error!("Could not connect to primary worker");
				return;
			}
		}
	});
	client.join().unwrap();

	match port_out.recv() {
		Ok(p) => Ok(p),
		Err(e) => {
			error!("[-] Could not connect to primary worker, returning");
			return Err(())
		},
	}
}

pub fn vec_to_h256(vec: Vec<u8>) -> H256 {
	let mut hash: [u8; 32] = Default::default();
	hash.copy_from_slice(&vec);
	Hash::from(hash)
}
