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

use crate::error::Error;
use base58::{FromBase58, ToBase58};
use clap::ArgMatches;
use frame_support::ensure;
use ita_stf::ShardIdentifier;
use itp_enclave_api::enclave_base::EnclaveBase;
use log::{debug, info};
use std::path::Path;

pub fn extract_shard<E: EnclaveBase>(m: &ArgMatches<'_>, enclave_api: &E) -> ShardIdentifier {
	match m.value_of("shard") {
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

pub fn hex_encode(data: Vec<u8>) -> String {
	let mut hex_str = hex::encode(data);
	hex_str.insert_str(0, "0x");
	hex_str
}

pub fn write_slice_and_whitespace_pad(writable: &mut [u8], data: Vec<u8>) -> Result<(), Error> {
	ensure!(
		data.len() <= writable.len(),
		Error::InsufficientBufferSize(writable.len(), data.len())
	);
	let (left, right) = writable.split_at_mut(data.len());
	left.clone_from_slice(&data);
	// fill the right side with whitespace
	right.iter_mut().for_each(|x| *x = 0x20);
	Ok(())
}

pub fn check_files() {
	use itp_settings::files::{
		ENCLAVE_FILE, RA_API_KEY_FILE, RA_SPID_FILE, SHIELDING_KEY_FILE, SIGNING_KEY_FILE,
	};
	debug!("*** Check files");
	let files =
		vec![ENCLAVE_FILE, SHIELDING_KEY_FILE, SIGNING_KEY_FILE, RA_SPID_FILE, RA_API_KEY_FILE];
	for f in files.iter() {
		assert!(Path::new(f).exists(), "File doesn't exist: {}", f);
	}
}

#[cfg(test)]
mod tests {

	use super::*;
	use std::assert_matches::assert_matches;

	#[test]
	fn write_slice_and_whitespace_pad_returns_error_if_buffer_too_small() {
		let mut writable = vec![0; 32];
		let data = vec![1; 33];
		assert_matches!(
			write_slice_and_whitespace_pad(&mut writable, data),
			Err(Error::InsufficientBufferSize(_, _))
		);
	}
}
