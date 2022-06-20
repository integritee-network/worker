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

use crate::{
	error::Error,
	test_utils::{
		create_signed_block_with_parenthash as create_signed_block, default_shard,
		fill_storage_with_blocks, get_storage,
	},
};
use sidechain_primitives::{traits::SignedBlock, types::BlockHash};
use std::assert_matches::assert_matches;

#[test]
fn get_blocks_after_works_for_regular_case() {
	let block_1 = create_signed_block(1, BlockHash::default());
	let block_2 = create_signed_block(2, block_1.hash());
	let block_3 = create_signed_block(3, block_2.hash());
	let block_4 = create_signed_block(4, block_3.hash());

	let temp_dir =
		fill_storage_with_blocks(vec![block_1.clone(), block_2.clone(), block_3, block_4.clone()]);

	{
		let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
		let blocks_after_1 = updated_sidechain_db
			.get_blocks_after(&block_1.hash(), &default_shard())
			.unwrap();

		assert_eq!(3, blocks_after_1.len());
		assert_eq!(block_2.hash(), blocks_after_1.first().unwrap().hash());
		assert_eq!(block_4.hash(), blocks_after_1.last().unwrap().hash());
	}
}

#[test]
fn get_blocks_after_returns_empty_vec_if_block_not_found() {
	let block_1 = create_signed_block(1, BlockHash::random());

	let temp_dir = fill_storage_with_blocks(vec![block_1.clone()]);

	{
		let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
		let block_hash = BlockHash::from_low_u64_be(1);
		// Off-chance that random() generates exactly the same hash
		assert_ne!(block_1.hash(), block_hash);

		assert_eq!(
			updated_sidechain_db.get_blocks_after(&block_hash, &default_shard()).unwrap(),
			Vec::new()
		);
	}
}

#[test]
fn get_blocks_returns_none_if_last_is_already_most_recent_block() {
	let block_1 = create_signed_block(1, BlockHash::random());

	let temp_dir = fill_storage_with_blocks(vec![block_1.clone()]);

	{
		let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());

		assert_eq!(
			updated_sidechain_db
				.get_blocks_after(&block_1.hash(), &default_shard())
				.unwrap(),
			Vec::new()
		);
	}
}

#[test]
fn get_blocks_after_returns_all_blocks_if_last_known_is_default() {
	let block_1 = create_signed_block(1, BlockHash::default());
	let block_2 = create_signed_block(2, block_1.hash());
	let block_3 = create_signed_block(3, block_2.hash());

	let blocks = vec![block_1.clone(), block_2.clone(), block_3.clone()];

	let temp_dir = fill_storage_with_blocks(blocks.clone());

	{
		let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
		let default_hash = BlockHash::default();

		assert_eq!(
			updated_sidechain_db.get_blocks_after(&default_hash, &default_shard()).unwrap(),
			blocks
		);
	}
}

#[test]
fn given_block_with_invalid_ancestry_returns_error() {
	let block_1 = create_signed_block(1, BlockHash::default());
	// Should be block_1 hash, but we deliberately introduce an invalid parent hash.
	let block_2 = create_signed_block(2, BlockHash::random());

	let temp_dir = fill_storage_with_blocks(vec![block_1.clone(), block_2]);

	{
		let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());

		assert_matches!(
			updated_sidechain_db.get_blocks_after(&block_1.hash(), &default_shard()),
			Err(Error::FailedToFindParentBlock)
		);
	}
}
