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

use crate::test_utils::{
	create_signed_block_with_parenthash as create_signed_block, default_shard,
	fill_storage_with_blocks, get_storage,
};
use itp_types::BlockHash;
use sidechain_primitives::traits::SignedBlock;

#[test]
fn get_blocks_in_range_works_for_regular_case() {
	let block_1 = create_signed_block(1, BlockHash::default());
	let block_2 = create_signed_block(2, block_1.hash());
	let block_3 = create_signed_block(3, block_2.hash());
	let block_4 = create_signed_block(4, block_3.hash());
	let block_5 = create_signed_block(5, block_4.hash());

	let temp_dir = fill_storage_with_blocks(vec![
		block_1.clone(),
		block_2.clone(),
		block_3,
		block_4.clone(),
		block_5.clone(),
	]);

	{
		let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
		let blocks_2_to_4 = updated_sidechain_db
			.get_blocks_in_range(&block_1.hash(), &block_5.hash(), &default_shard())
			.unwrap();

		assert_eq!(3, blocks_2_to_4.len());
		assert_eq!(block_2.hash(), blocks_2_to_4.first().unwrap().hash());
		assert_eq!(block_4.hash(), blocks_2_to_4.last().unwrap().hash());
	}
}

#[test]
fn get_blocks_in_range_returns_empty_vec_if_from_is_invalid() {
	let block_1 = create_signed_block(1, BlockHash::default());
	let block_2 = create_signed_block(2, block_1.hash());
	let block_3 = create_signed_block(3, block_2.hash());
	let block_4 = create_signed_block(4, block_3.hash());

	let temp_dir = fill_storage_with_blocks(vec![
		block_1.clone(),
		block_2.clone(),
		block_3.clone(),
		block_4.clone(),
	]);

	{
		let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
		let invalid_block_hash = BlockHash::from_low_u64_be(1);

		assert!(updated_sidechain_db
			.get_blocks_in_range(&invalid_block_hash, &block_3.hash(), &default_shard())
			.unwrap()
			.is_empty());
	}
}

#[test]
fn get_blocks_in_range_returns_all_blocks_if_upper_bound_is_invalid() {
	let block_1 = create_signed_block(1, BlockHash::default());
	let block_2 = create_signed_block(2, block_1.hash());
	let block_3 = create_signed_block(3, block_2.hash());
	let block_4 = create_signed_block(4, block_3.hash());
	let block_5 = create_signed_block(5, block_4.hash());

	let temp_dir = fill_storage_with_blocks(vec![
		block_1.clone(),
		block_2.clone(),
		block_3.clone(),
		block_4.clone(),
		block_5.clone(),
	]);

	{
		let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
		let blocks_in_range = updated_sidechain_db
			.get_blocks_in_range(&block_2.hash(), &BlockHash::from_low_u64_be(1), &default_shard())
			.unwrap();

		assert_eq!(3, blocks_in_range.len());
		assert_eq!(block_3.hash(), blocks_in_range.first().unwrap().hash());
		assert_eq!(block_5.hash(), blocks_in_range.last().unwrap().hash());
	}
}
