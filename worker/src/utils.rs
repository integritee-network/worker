use substratee_stf::ShardIdentifier;
use clap::ArgMatches;
use base58::{FromBase58, ToBase58};
use log::info;
use crate::enclave::api::{enclave_init, enclave_mrenclave};

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
