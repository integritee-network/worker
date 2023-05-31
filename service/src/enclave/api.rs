/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

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

use crate::config::Config;
use itp_enclave_api::{
	enclave_base::EnclaveBase, error::Error as EnclaveApiError, Enclave, EnclaveResult,
};
use itp_settings::files::{ENCLAVE_FILE, ENCLAVE_TOKEN};
use log::*;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::{
	fs::File,
	io::{Read, Write},
	path::PathBuf,
};

pub fn enclave_init(config: &Config) -> EnclaveResult<Enclave> {
	const LEN: usize = 1024;
	let mut launch_token = [0; LEN];
	let mut launch_token_updated = 0;

	// Step 1: try to retrieve the launch token saved by last transaction
	//         if there is no token, then create a new one.
	//
	// try to get the token saved in $HOME */
	let mut home_dir = PathBuf::new();
	let use_token = match dirs::home_dir() {
		Some(path) => {
			info!("[+] Home dir is {}", path.display());
			home_dir = path;
			true
		},
		None => {
			error!("[-] Cannot get home dir");
			false
		},
	};
	let token_file = home_dir.join(ENCLAVE_TOKEN);
	if use_token {
		match File::open(&token_file) {
			Err(_) => {
				info!(
					"[-] Token file {} not found! Will create one.",
					token_file.as_path().to_str().unwrap()
				);
			},
			Ok(mut f) => {
				info!("[+] Open token file success! ");
				match f.read(&mut launch_token) {
					Ok(LEN) => {
						info!("[+] Token file valid!");
					},
					_ => info!("[+] Token file invalid, will create new token file"),
				}
			},
		}
	}

	// Step 2: call sgx_create_enclave to initialize an enclave instance
	// Debug Support: 1 = debug mode, 0 = not debug mode
	#[cfg(not(feature = "production"))]
	let debug = 1;
	#[cfg(feature = "production")]
	let debug = 0;

	let mut misc_attr =
		sgx_misc_attribute_t { secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 }, misc_select: 0 };
	let enclave = (SgxEnclave::create(
		ENCLAVE_FILE,
		debug,
		&mut launch_token,
		&mut launch_token_updated,
		&mut misc_attr,
	))
	.map_err(EnclaveApiError::Sgx)?;

	// Step 3: save the launch token if it is updated
	if use_token && launch_token_updated != 0 {
		// reopen the file with write capability
		match File::create(&token_file) {
			Ok(mut f) => match f.write_all(&launch_token) {
				Ok(()) => info!("[+] Saved updated launch token!"),
				Err(_) => error!("[-] Failed to save updated launch token!"),
			},
			Err(_) => {
				warn!("[-] Failed to save updated enclave token, but doesn't matter");
			},
		}
	}

	// create an enclave API and initialize it
	let enclave_api = Enclave::new(enclave);
	enclave_api.init(
		&config.mu_ra_url_external(),
		&config.untrusted_worker_url_external(),
		&config.data_dir().display().to_string(),
	)?;

	Ok(enclave_api)
}
