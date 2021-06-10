use substratee_stf::ShardIdentifier;
use clap::ArgMatches;
use base58::{FromBase58, ToBase58};
use log::{info, debug};
use crate::enclave::api::{enclave_init, enclave_mrenclave};
use std::path::Path;

pub fn extract_shard(m: &ArgMatches<'_>) -> ShardIdentifier {
	match m.value_of("shard") {
		Some(value) => {
			let shard_vec = value.from_base58().expect("shard must be hex encoded");
			let mut shard = [0u8; 32];
			shard.copy_from_slice(&shard_vec[..]);
			shard.into()
		}
		_ => {
			let enclave = enclave_init().unwrap();
			let mrenclave = enclave_mrenclave(enclave.geteid()).unwrap();
			info!(
				"no shard specified. using mrenclave as id: {}",
				mrenclave.to_base58()
			);
			ShardIdentifier::from_slice(&mrenclave[..])
		}
	}
}

pub fn hex_encode(data: Vec<u8>) -> String {
	let mut hex_str = hex::encode(data);
	hex_str.insert_str(0, "0x");
	hex_str
}

pub fn check_files() {
	use substratee_settings::files::{
		SIGNING_KEY_FILE, SHIELDING_KEY_FILE, ENCLAVE_FILE,
		RA_SPID_FILE, RA_API_KEY_FILE,
	};
	debug!("*** Check files");
	let files = vec![
		ENCLAVE_FILE,
		SHIELDING_KEY_FILE,
		SIGNING_KEY_FILE,
		RA_SPID_FILE,
		RA_API_KEY_FILE,
	];
	for f in files.iter() {
		if !Path::new(f).exists() {
			panic!("file doesn't exist: {}", f);
		}
	}
}