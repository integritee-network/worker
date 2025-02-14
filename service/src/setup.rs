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
use itp_settings::files::{
	INTEGRITEE_PARENTCHAIN_LIGHT_CLIENT_DB_PATH, SHARDS_PATH, SIDECHAIN_BLOCKS_DB_STORAGE_PATH,
	TARGET_A_PARENTCHAIN_LIGHT_CLIENT_DB_PATH, TARGET_B_PARENTCHAIN_LIGHT_CLIENT_DB_PATH,
};
use log::info;
#[cfg(feature = "link-binary")]
pub(crate) use needs_enclave::{
	generate_shielding_key_file, generate_signing_key_file, init_shard, initialize_shard_and_keys,
};
use std::{
	fs,
	path::{Path, PathBuf},
};

#[cfg(feature = "link-binary")]
mod needs_enclave {
	use crate::error::{Error, ServiceResult};
	use codec::Encode;
	use itp_enclave_api::{enclave_base::EnclaveBase, Enclave};
	use itp_settings::files::{
		INTEGRITEE_PARENTCHAIN_LIGHT_CLIENT_DB_PATH, SHARDS_PATH, SHIELDING_KEY_FILE,
		SIDECHAIN_BLOCKS_DB_STORAGE_PATH, SIGNING_KEY_FILE,
		TARGET_A_PARENTCHAIN_LIGHT_CLIENT_DB_PATH, TARGET_B_PARENTCHAIN_LIGHT_CLIENT_DB_PATH,
	};
	use itp_types::ShardIdentifier;
	use log::*;
	use std::{fs, fs::File, path::Path};

	/// Initializes the shard and generates the key files.
	pub(crate) fn initialize_shard_and_keys(
		enclave: &Enclave,
		shard_identifier: &ShardIdentifier,
	) -> ServiceResult<()> {
		println!("[+] Initialize the shard: {:?}", shard_identifier);
		init_shard(enclave, shard_identifier);

		let pubkey = enclave.get_ecc_signing_pubkey().unwrap();
		debug!("Enclave signing key (public) raw: {:?}", pubkey);
		let pubkey = enclave.get_rsa_shielding_pubkey().unwrap();
		debug!("Enclave shielding key (public) raw (may be overwritten later): {:?}", pubkey);
		Ok(())
	}

	pub(crate) fn init_shard(enclave: &Enclave, shard_identifier: &ShardIdentifier) {
		use base58::ToBase58;

		match enclave.init_shard(shard_identifier.encode()) {
			Err(e) => {
				println!(
					"Failed to initialize shard {:?}: {:?}",
					shard_identifier.0.to_base58(),
					e
				);
			},
			Ok(_) => {
				println!("Successfully initialized shard {:?}", shard_identifier.0.to_base58());
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
}

/// Purge all worker files in a given path.
pub(crate) fn purge_shards_unless_protected(root_directory: &Path) -> ServiceResult<()> {
	let mut protectfile = PathBuf::from(root_directory);
	protectfile.push("shards.protect");
	if fs::metadata(protectfile.clone()).is_ok() {
		println!("   all shards and sidechain db are protected by {:?}", protectfile);
	} else {
		println!("[+] Purge all shards and sidechain blocks from previous runs");
		remove_dir_if_it_exists(root_directory, SHARDS_PATH)?;
		remove_dir_if_it_exists(root_directory, SIDECHAIN_BLOCKS_DB_STORAGE_PATH)?;
	}
	Ok(())
}

pub(crate) fn purge_integritee_lcdb_unless_protected(root_directory: &Path) -> ServiceResult<()> {
	let mut protectfile = PathBuf::from(root_directory);
	protectfile.push("integritee_lcdb.protect");
	if fs::metadata(protectfile.clone()).is_ok() {
		println!("   Integritee light-client dB is protected by {:?}", protectfile);
	} else {
		println!("[+] Purge Integritee light-client db from previous runs");
		remove_dir_if_it_exists(root_directory, INTEGRITEE_PARENTCHAIN_LIGHT_CLIENT_DB_PATH)?;
	}
	Ok(())
}

pub(crate) fn purge_target_a_lcdb_unless_protected(root_directory: &Path) -> ServiceResult<()> {
	let mut protectfile = PathBuf::from(root_directory);
	protectfile.push("target_a_lcdb.protect");
	if fs::metadata(protectfile.clone()).is_ok() {
		println!("   TargetA light-client dB is protected by {:?}", protectfile);
	} else {
		println!("[+] Purge TargetA light-client db from previous runs");
		remove_dir_if_it_exists(root_directory, TARGET_A_PARENTCHAIN_LIGHT_CLIENT_DB_PATH)?;
	}
	Ok(())
}

pub(crate) fn purge_target_b_lcdb_unless_protected(root_directory: &Path) -> ServiceResult<()> {
	let mut protectfile = PathBuf::from(root_directory);
	protectfile.push("target_b_lcdb.protect");
	if fs::metadata(protectfile.clone()).is_ok() {
		println!("   TargetB light-client dB is protected by {:?}", protectfile);
	} else {
		println!("[+] Purge TargetB light-client db from previous runs");
		remove_dir_if_it_exists(root_directory, TARGET_B_PARENTCHAIN_LIGHT_CLIENT_DB_PATH)?;
	}
	Ok(())
}

fn remove_dir_if_it_exists(root_directory: &Path, dir_name: &str) -> ServiceResult<()> {
	let directory_path = root_directory.join(dir_name);
	if directory_path.exists() {
		info!("removing directory: {}", directory_path.display());
		fs::remove_dir_all(directory_path).map_err(|e| Error::Custom(e.into()))?;
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use itp_settings::files::{SHARDS_PATH, TARGET_A_PARENTCHAIN_LIGHT_CLIENT_DB_PATH};
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

		let sidechain_db_path = root_directory.join(SIDECHAIN_BLOCKS_DB_STORAGE_PATH);
		fs::create_dir_all(&sidechain_db_path).unwrap();
		fs::File::create(&sidechain_db_path.join("sidechain_db_1.bin")).unwrap();
		fs::File::create(&sidechain_db_path.join("sidechain_db_2.bin")).unwrap();
		fs::File::create(&sidechain_db_path.join("sidechain_db_3.bin")).unwrap();

		fs::create_dir_all(&root_directory.join(INTEGRITEE_PARENTCHAIN_LIGHT_CLIENT_DB_PATH))
			.unwrap();
		fs::create_dir_all(&root_directory.join(TARGET_A_PARENTCHAIN_LIGHT_CLIENT_DB_PATH))
			.unwrap();
		fs::create_dir_all(&root_directory.join(TARGET_B_PARENTCHAIN_LIGHT_CLIENT_DB_PATH))
			.unwrap();

		purge_shards_unless_protected(&root_directory).unwrap();
		assert!(!shards_path.exists());
		assert!(!sidechain_db_path.exists());
		purge_integritee_lcdb_unless_protected(&root_directory).unwrap();
		assert!(!root_directory.join(INTEGRITEE_PARENTCHAIN_LIGHT_CLIENT_DB_PATH).exists());
		purge_target_a_lcdb_unless_protected(&root_directory).unwrap();
		assert!(!root_directory.join(TARGET_A_PARENTCHAIN_LIGHT_CLIENT_DB_PATH).exists());
		purge_target_b_lcdb_unless_protected(&root_directory).unwrap();
		assert!(!root_directory.join(TARGET_B_PARENTCHAIN_LIGHT_CLIENT_DB_PATH).exists());
	}

	#[test]
	fn purge_files_succeeds_when_no_files_exist() {
		let test_directory_handle = TestDirectoryHandle::new(PathBuf::from(
			"test_purge_files_succeeds_when_no_files_exist",
		));
		let root_directory = test_directory_handle.path();

		assert!(purge_shards_unless_protected(&root_directory).is_ok());
		assert!(purge_integritee_lcdb_unless_protected(&root_directory).is_ok());
		assert!(purge_target_a_lcdb_unless_protected(&root_directory).is_ok());
		assert!(purge_target_b_lcdb_unless_protected(&root_directory).is_ok());
	}

	#[test]
	fn purge_shards_protect_file_respected() {
		let test_directory_handle = TestDirectoryHandle::new(PathBuf::from("test_protect_shard"));
		let root_directory = test_directory_handle.path();

		let shards_path = root_directory.join(SHARDS_PATH);
		fs::create_dir_all(&shards_path).unwrap();
		fs::File::create(&shards_path.join("state_1.bin")).unwrap();
		fs::File::create(&shards_path.join("state_2.bin")).unwrap();

		let sidechain_db_path = root_directory.join(SIDECHAIN_BLOCKS_DB_STORAGE_PATH);
		fs::create_dir_all(&sidechain_db_path).unwrap();
		fs::File::create(&sidechain_db_path.join("sidechain_db_1.bin")).unwrap();
		fs::File::create(&sidechain_db_path.join("sidechain_db_2.bin")).unwrap();
		fs::File::create(&sidechain_db_path.join("sidechain_db_3.bin")).unwrap();

		let protector_path = root_directory.join("shards.protect");
		fs::File::create(&protector_path).unwrap();

		purge_shards_unless_protected(&root_directory).unwrap();
		assert!(shards_path.exists());
		assert!(sidechain_db_path.exists());

		fs::remove_file(&protector_path).unwrap();
		while protector_path.exists() {
			std::thread::sleep(std::time::Duration::from_millis(100));
		}
		purge_shards_unless_protected(&root_directory).unwrap();
		assert!(!shards_path.exists());
		assert!(!sidechain_db_path.exists());
	}

	#[test]
	fn purge_integritee_lcdb_protect_file_respected() {
		let test_directory_handle =
			TestDirectoryHandle::new(PathBuf::from("test_protect_integritee_lcdb"));
		let root_directory = test_directory_handle.path();

		let lcdb_path = root_directory.join(INTEGRITEE_PARENTCHAIN_LIGHT_CLIENT_DB_PATH);
		fs::create_dir_all(&lcdb_path).unwrap();

		let protector_path = root_directory.join("integritee_lcdb.protect");
		fs::File::create(&protector_path).unwrap();

		purge_integritee_lcdb_unless_protected(&root_directory).unwrap();
		assert!(lcdb_path.exists());

		fs::remove_file(&protector_path).unwrap();
		purge_integritee_lcdb_unless_protected(&root_directory).unwrap();
		assert!(!lcdb_path.exists());
	}

	#[test]
	fn purge_target_a_lcdb_protect_file_respected() {
		let test_directory_handle =
			TestDirectoryHandle::new(PathBuf::from("test_protect_target_a_lcdb"));
		let root_directory = test_directory_handle.path();

		let lcdb_path = root_directory.join(TARGET_A_PARENTCHAIN_LIGHT_CLIENT_DB_PATH);
		fs::create_dir_all(&lcdb_path).unwrap();

		let protector_path = root_directory.join("target_a_lcdb.protect");
		fs::File::create(&protector_path).unwrap();

		purge_target_a_lcdb_unless_protected(&root_directory).unwrap();
		assert!(lcdb_path.exists());

		fs::remove_file(&protector_path).unwrap();
		purge_target_a_lcdb_unless_protected(&root_directory).unwrap();
		assert!(!lcdb_path.exists());
	}

	#[test]
	fn purge_target_b_lcdb_protect_file_respected() {
		let test_directory_handle =
			TestDirectoryHandle::new(PathBuf::from("test_protect_target_b_lcdb"));
		let root_directory = test_directory_handle.path();

		let lcdb_path = root_directory.join(TARGET_B_PARENTCHAIN_LIGHT_CLIENT_DB_PATH);
		fs::create_dir_all(&lcdb_path).unwrap();

		let protector_path = root_directory.join("target_b_lcdb.protect");
		fs::File::create(&protector_path).unwrap();

		purge_target_b_lcdb_unless_protected(&root_directory).unwrap();
		assert!(lcdb_path.exists());

		fs::remove_file(&protector_path).unwrap();
		purge_target_b_lcdb_unless_protected(&root_directory).unwrap();
		assert!(!lcdb_path.exists());
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
