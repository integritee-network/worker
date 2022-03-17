/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

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

use crate::storage::SidechainStorage;
use itp_types::ShardIdentifier;
use its_primitives::types::{BlockHash, SignedBlock as SignedSidechainBlock};
use its_test::sidechain_block_builder::SidechainBlockBuilder;
use sp_core::{crypto::Pair, ed25519, H256};
use std::{
	path::PathBuf,
	time::{SystemTime, UNIX_EPOCH},
	vec::Vec,
};
use temp_dir::TempDir;

pub fn fill_storage_with_blocks(blocks: Vec<SignedSidechainBlock>) -> TempDir {
	let dir = create_temp_dir();
	let mut sidechain_db = get_storage(dir.path().to_path_buf());
	sidechain_db.store_blocks(blocks).unwrap();
	dir
}

pub fn create_temp_dir() -> TempDir {
	TempDir::new().unwrap()
}

pub fn get_storage(path: PathBuf) -> SidechainStorage<SignedSidechainBlock> {
	SidechainStorage::<SignedSidechainBlock>::new(path).unwrap()
}

pub fn default_shard() -> ShardIdentifier {
	ShardIdentifier::default()
}

pub fn create_signed_block_with_parenthash(
	block_number: u64,
	parent_hash: BlockHash,
) -> SignedSidechainBlock {
	default_block_builder()
		.with_parent_hash(parent_hash)
		.with_number(block_number)
		.build_signed()
}

pub fn create_signed_block_with_shard(
	block_number: u64,
	shard: ShardIdentifier,
) -> SignedSidechainBlock {
	default_block_builder()
		.with_shard(shard)
		.with_number(block_number)
		.build_signed()
}

fn default_block_builder() -> SidechainBlockBuilder {
	SidechainBlockBuilder::default()
		.with_signer(ed25519::Pair::from_string("//Alice", None).unwrap())
		.with_parent_hash(H256::random())
		.with_parentchain_block_hash(H256::random())
		.with_timestamp(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64)
		.with_shard(default_shard())
		.with_number(Default::default())
}
