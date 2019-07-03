use log::info;
use my_node_runtime::Hash;
use parity_codec::{Decode, Encode};
use primitive_types::{H256, U256};
use substrate_api_client::{Api, hexstr_to_u256, hexstr_to_vec};

pub fn get_worker_info(api: &substrate_api_client::Api, index: u64) {
	info!("[>] Get worker's URL");
	let result_str = api.get_storage("substraTEERegistry", "EnclaveRegistry", Some((index).encode())).unwrap();
	info!("Storage hex_str: {}", result_str);

	let enc = hexstr_to_enclave(result_str);
	println!("[+]: Workers Pubkey is {:?}", &enc.pubkey);
	println!("[+]: Workers URL is {:?}", std::str::from_utf8(&enc.url).unwrap());
}

pub fn get_worker_amount(api: &substrate_api_client::Api) -> u64 {
	let result_str = api.get_storage("substraTEERegistry", "EnclaveCount", None).unwrap();
	let amount = hexstr_to_u64(result_str);
	println!("[+]: Amount of Registered Workers {:?}", amount);
	amount
}

fn hexstr_to_enclave(hexstr: String) -> Enclave {
	let mut unhex = hexstr_to_vec(hexstr);
	let (h, url) = unhex.split_at_mut(32 as usize);
	let mut hash: [u8; 32] = Default::default();
	hash.copy_from_slice(&h);
	let key = Hash::from(hash);

	Enclave {
		pubkey: key,
		// Fixme: There are some bytes left that contain metadata about the linkable map.
		// This may be the reason I was not able to do automated deserialization.
		url: url[1..url.len() - 10].to_vec()
	}
}

pub fn hexstr_to_u64(hexstr: String) -> u64 {
	let unhex = hexstr_to_vec(hexstr);
	let mut gh: [u8; 8] = Default::default();
	gh.copy_from_slice(&unhex);

	u64::from_le_bytes(gh)
}

#[derive(Encode, Decode, Default, Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Enclave {
	pubkey: H256,
	// utf8 encoded url
	url: Vec<u8>
}

#[cfg(test)]
mod tests {
	use substrate_api_client::Api;

	use super::*;

	#[test]
	// test requires one registered enclave in substratee_registry
	fn get_worker_enclave_should_work() {
		let mut api: substrate_api_client::Api = Api::new(format!("ws://127.0.0.1:9991"));
		api.init();
		get_worker_amount(&api);
		get_worker_info(&api, 0);
	}
}

