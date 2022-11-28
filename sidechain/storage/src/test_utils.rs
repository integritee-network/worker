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
use itp_time_utils::now_as_millis;
use itp_types::ShardIdentifier;
use its_primitives::types::{BlockHash, SignedBlock as SignedSidechainBlock};
use its_test::{
	sidechain_block_builder::SidechainBlockBuilder,
	sidechain_block_data_builder::SidechainBlockDataBuilder,
	sidechain_header_builder::SidechainHeaderBuilder,
};
use sp_core::{crypto::Pair, ed25519, H256};
use std::{path::PathBuf, vec::Vec};
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
	let header = default_header_builder()
		.with_parent_hash(parent_hash)
		.with_block_number(block_number)
		.build();

	let block_data = default_block_data_builder().build();

	SidechainBlockBuilder::default()
		.with_header(header)
		.with_block_data(block_data)
		.build_signed()
}

pub fn create_signed_block_with_shard(
	block_number: u64,
	shard: ShardIdentifier,
) -> SignedSidechainBlock {
	let header = default_header_builder()
		.with_shard(shard)
		.with_block_number(block_number)
		.build();

	let block_data = default_block_data_builder().build();

	SidechainBlockBuilder::default()
		.with_header(header)
		.with_block_data(block_data)
		.build_signed()
}

fn default_header_builder() -> SidechainHeaderBuilder {
	SidechainHeaderBuilder::default()
		.with_parent_hash(H256::random())
		.with_block_number(Default::default())
		.with_shard(default_shard())
}

fn default_block_data_builder() -> SidechainBlockDataBuilder {
	SidechainBlockDataBuilder::default()
		.with_timestamp(now_as_millis())
		.with_layer_one_head(H256::random())
		.with_signer(ed25519::Pair::from_string("//Alice", None).unwrap())
}
