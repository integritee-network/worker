use substratee_api_client_extensions::{SubstrateeRegistryApi, ApiResult};
use substratee_node_primitives::{Enclave, ShardIdentifier};
use primitive_types::H256;

pub struct TestNodeApi;

const W1_URL: &str = "127.0.0.1:2222";
const W2_URL: &str = "127.0.0.1:2223";

fn enclaves() -> Vec<Enclave> {
	vec![
		Enclave::new(
			H256::random().to_fixed_bytes().into(),
			H256::random().to_fixed_bytes().into(),
			1,
			W1_URL.into(),
		),
		Enclave::new(
			H256::random().to_fixed_bytes().into(),
			H256::random().to_fixed_bytes().into(),
			2,
			W2_URL.into(),
		),
	]
}

impl SubstrateeRegistryApi for TestNodeApi {

	fn enclave(&self, index: u64) -> ApiResult<Option<Enclave>> {
		Ok(Some(enclaves().remove(index as usize)))
	}
	fn enclave_count(&self) -> ApiResult<u64> {
		unreachable!()
	}

	fn all_enclaves(&self) -> ApiResult<Vec<Enclave>> {
		// the args are okay here. The IDE does not grasp types depending on feature flags.
		Ok(enclaves())
	}

	fn worker_for_shard(&self, _: &ShardIdentifier) -> ApiResult<Option<Enclave>> {
		unreachable!()
	}
	fn latest_ipfs_hash(&self, _: &ShardIdentifier) -> ApiResult<Option<[u8; 46]>> {
		unreachable!()
	}
}