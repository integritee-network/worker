use parity_scale_codec::Encode;

use substratee_enclave_api::{EnclaveApi, EnclaveResult};
use substratee_worker_primitives::block::{SignedBlock, Block};
use substratee_worker_primitives::{ShardIdentifier, RpcResponse};
use sp_core::crypto::AccountId32;

pub struct TestEnclave;

impl EnclaveApi for TestEnclave {
	fn rpc(&self, _request: Vec<u8>) -> EnclaveResult<Vec<u8>> {
		Ok(RpcResponse {
			jsonrpc: "mock_response".into(),
			result: "null".encode(),
			id: 1
		}.encode())
	}
}

pub fn test_sidechain_block() -> SignedBlock {
	use sp_core::{H256, Pair};

	let signer_pair = sp_core::ed25519::Pair::from_string("//Alice", None).unwrap();
	let author: AccountId32 = signer_pair.public().into();
	let block_number: u64 = 0;
	let parent_hash = H256::random();
	let layer_one_head = H256::random();
	let signed_top_hashes = vec![];
	let encrypted_payload: Vec<u8> = vec![];
	let shard = ShardIdentifier::default();

	// when
	let block = Block::construct_block(
		author,
		block_number,
		parent_hash.clone(),
		layer_one_head.clone(),
		shard.clone(),
		signed_top_hashes.clone(),
		encrypted_payload.clone(),
	);
	block.sign(&signer_pair)
}