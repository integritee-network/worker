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

use crate::error::{Error, ServiceResult};
use codec::Encode;
use itp_enclave_api::{enclave_base::EnclaveBase, Enclave};
use itp_settings::files::{
	LIGHT_CLIENT_DB_PATH, SHARDS_PATH, SHIELDING_KEY_FILE, SIDECHAIN_STORAGE_PATH, SIGNING_KEY_FILE,
};
use itp_types::ShardIdentifier;
use log::*;
use std::{fs, fs::File, path::Path};

/// Purge all worker files from `dir`.
pub(crate) fn purge_files_from_dir(dir: &Path) -> ServiceResult<()> {
	println!("[+] Performing a clean reset of the worker");

	println!("[+] Purge all files from previous runs");
	purge_files(dir)?;

	Ok(())
}

/// Initializes the shard and generates the key files.
pub(crate) fn initialize_shard_and_keys(
	enclave: &Enclave,
	shard_identifier: &ShardIdentifier,
) -> ServiceResult<()> {
	println!("[+] Initialize the shard");
	init_shard(enclave, shard_identifier);

	println!("[+] Generate key files");
	generate_signing_key_file(enclave);
	generate_shielding_key_file(enclave);

	Ok(())
}

pub(crate) fn init_shard(enclave: &Enclave, shard_identifier: &ShardIdentifier) {
	match enclave.init_shard(shard_identifier.encode()) {
		Err(e) => {
			println!("Failed to initialize shard {:?}: {:?}", shard_identifier, e);
		},
		Ok(_) => {
			println!("Successfully initialized shard {:?}", shard_identifier);
		},
	}
}

pub(crate) fn generate_signing_key_file(enclave: &Enclave) {
	info!("*** Get the signing key from the TEE\n");
	let pubkey = enclave.get_ecc_signing_pubkey().unwrap();
	debug!("[+] Signing key raw: {:?}", pubkey);
	match fs::write(SIGNING_KEY_FILE, pubkey) {
		Err(x) => {
			error!("[-] Failed to write '{}'. {}", SIGNING_KEY_FILE, x);
		},
		_ => {
			println!("[+] File '{}' written successfully", SIGNING_KEY_FILE);
		},
	}
}

pub(crate) fn generate_shielding_key_file(enclave: &Enclave) {
	info!("*** Get the public key from the TEE\n");
	let pubkey = enclave.get_rsa_shielding_pubkey().unwrap();
	let file = File::create(SHIELDING_KEY_FILE).unwrap();
	match serde_json::to_writer(file, &pubkey) {
		Err(x) => {
			error!("[-] Failed to write '{}'. {}", SHIELDING_KEY_FILE, x);
		},
		_ => {
			println!("[+] File '{}' written successfully", SHIELDING_KEY_FILE);
		},
	}
}

/// Purge all worker files in a given path.
fn purge_files(root_directory: &Path) -> ServiceResult<()> {
	remove_dir_if_it_exists(root_directory, SHARDS_PATH)?;
	remove_dir_if_it_exists(root_directory, SIDECHAIN_STORAGE_PATH)?;

	remove_dir_if_it_exists(root_directory, LIGHT_CLIENT_DB_PATH)?;

	Ok(())
}

fn remove_dir_if_it_exists(root_directory: &Path, dir_name: &str) -> ServiceResult<()> {
	let directory_path = root_directory.join(dir_name);
	if directory_path.exists() {
		fs::remove_dir_all(directory_path).map_err(|e| Error::Custom(e.into()))?;
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use itp_settings::files::SHARDS_PATH;
	use std::{fs, path::PathBuf};

	#[test]
	fn purge_files_deletes_all_relevant_files() {
		let test_directory_handle =
			TestDirectoryHandle::new(PathBuf::from("test_purge_files_deletes_all_relevant_files"));
		let root_directory = test_directory_handle.path();

		let shards_path = root_directory.join(SHARDS_PATH);
		fs::create_dir_all(&shards_path).unwrap();
		fs::File::create(&shards_path.join("state_1.bin")).unwrap();
		fs::File::create(&shards_path.join("state_2.bin")).unwrap();

		let sidechain_db_path = root_directory.join(SIDECHAIN_STORAGE_PATH);
		fs::create_dir_all(&sidechain_db_path).unwrap();
		fs::File::create(&sidechain_db_path.join("sidechain_db_1.bin")).unwrap();
		fs::File::create(&sidechain_db_path.join("sidechain_db_2.bin")).unwrap();
		fs::File::create(&sidechain_db_path.join("sidechain_db_3.bin")).unwrap();

		fs::create_dir_all(&root_directory.join(LIGHT_CLIENT_DB_PATH)).unwrap();

		purge_files(&root_directory).unwrap();

		assert!(!shards_path.exists());
		assert!(!sidechain_db_path.exists());
		assert!(!root_directory.join(LIGHT_CLIENT_DB_PATH).exists());
	}

	#[test]
	fn purge_files_succeeds_when_no_files_exist() {
		let test_directory_handle = TestDirectoryHandle::new(PathBuf::from(
			"test_purge_files_succeeds_when_no_files_exist",
		));
		let root_directory = test_directory_handle.path();

		assert!(purge_files(&root_directory).is_ok());
	}

	/// Directory handle to automatically initialize a directory
	/// and upon dropping the reference, removing it again.
	struct TestDirectoryHandle {
		path: PathBuf,
	}

	impl TestDirectoryHandle {
		pub fn new(path: PathBuf) -> Self {
			let test_path = std::env::current_dir().unwrap().join(&path);
			fs::create_dir_all(&test_path).unwrap();
			TestDirectoryHandle { path: test_path }
		}

		pub fn path(&self) -> &PathBuf {
			&self.path
		}
	}

	impl Drop for TestDirectoryHandle {
		fn drop(&mut self) {
			if self.path.exists() {
				fs::remove_dir_all(&self.path).unwrap();
			}
		}
	}
}
