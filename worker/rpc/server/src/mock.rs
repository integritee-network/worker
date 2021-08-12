use parity_scale_codec::Encode;

use sp_core::crypto::AccountId32;
use substratee_enclave_api::{direct_request::DirectRequest, EnclaveResult};
use substratee_worker_primitives::{
	block::{Block, SignedBlock},
	traits::{Block as BlockT, SignBlock},
	RpcResponse, ShardIdentifier,
};

pub struct TestEnclave;

impl DirectRequest for TestEnclave {
	fn rpc(&self, _request: Vec<u8>) -> EnclaveResult<Vec<u8>> {
		Ok(RpcResponse { jsonrpc: "mock_response".into(), result: "null".encode(), id: 1 }.encode())
	}

	fn initialize_pool(&self) -> EnclaveResult<()> {
		unreachable!()
	}
}

// todo: this is a duplicate that is also defined in the worker. We should extract an independent
// test-utils crate because here we don't want to depend on the worker itself.
pub fn test_sidechain_block() -> SignedBlock {
	use sp_core::{Pair, H256};

	let signer_pair = sp_core::ed25519::Pair::from_string("//Alice", None).unwrap();
	let author: AccountId32 = signer_pair.public().into();
	let block_number: u64 = 0;
	let parent_hash = H256::random();
	let layer_one_head = H256::random();
	let signed_top_hashes = vec![];
	let encrypted_payload: Vec<u8> = vec![];
	let shard = ShardIdentifier::default();

	// when
	let block = Block::new(
		author,
		block_number,
		parent_hash.clone(),
		layer_one_head.clone(),
		shard.clone(),
		signed_top_hashes.clone(),
		encrypted_payload.clone(),
		10000,
	);
	block.sign_block(&signer_pair)
}
