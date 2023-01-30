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

use base58::{FromBase58, ToBase58};
use itp_enclave_api::enclave_base::EnclaveBase;
use itp_types::ShardIdentifier;
use log::info;

pub fn extract_shard<E: EnclaveBase>(
	maybe_shard_str: &Option<String>,
	enclave_api: &E,
) -> ShardIdentifier {
	match maybe_shard_str {
		Some(value) => {
			let shard_vec = value.from_base58().expect("shard must be hex encoded");
			let mut shard = [0u8; 32];
			shard.copy_from_slice(&shard_vec[..]);
			shard.into()
		},
		_ => {
			let mrenclave = enclave_api.get_mrenclave().unwrap();
			info!("no shard specified. using mrenclave as id: {}", mrenclave.to_base58());
			ShardIdentifier::from_slice(&mrenclave[..])
		},
	}
}

#[cfg(not(feature = "dcap"))]
pub fn check_files() {
	use itp_settings::files::{ENCLAVE_FILE, RA_API_KEY_FILE, RA_SPID_FILE};
	use log::debug;
	use std::path::Path;
	debug!("*** Check files");
	let files = [ENCLAVE_FILE, RA_SPID_FILE, RA_API_KEY_FILE];
	for f in files.iter() {
		assert!(Path::new(f).exists(), "File doesn't exist: {}", f);
	}
}
