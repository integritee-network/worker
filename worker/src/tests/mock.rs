use substratee_api_client_extensions::{ApiResult, PalletTeerexApi};
use substratee_node_primitives::{Enclave, ShardIdentifier};

pub struct TestNodeApi;

pub const W1_URL: &str = "127.0.0.1:2222";
pub const W2_URL: &str = "127.0.0.1:3333";

pub fn enclaves() -> Vec<Enclave> {
	vec![
		Enclave::new([0; 32].into(), [1; 32], 1, format!("ws://{}", W1_URL)),
		Enclave::new([2; 32].into(), [3; 32], 2, format!("ws://{}", W2_URL)),
	]
}

impl PalletTeerexApi for TestNodeApi {
	fn enclave(&self, index: u64) -> ApiResult<Option<Enclave>> {
		Ok(Some(enclaves().remove(index as usize)))
	}
	fn enclave_count(&self) -> ApiResult<u64> {
		unreachable!()
	}

	fn all_enclaves(&self) -> ApiResult<Vec<Enclave>> {
		Ok(enclaves())
	}

	fn worker_for_shard(&self, _: &ShardIdentifier) -> ApiResult<Option<Enclave>> {
		unreachable!()
	}
	fn latest_ipfs_hash(&self, _: &ShardIdentifier) -> ApiResult<Option<[u8; 46]>> {
		unreachable!()
	}
}
