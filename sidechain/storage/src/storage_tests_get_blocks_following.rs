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

use crate::{error::Error, test_db_fixture::TestDbFixture};
use itp_types::ShardIdentifier;
use its_primitives::{
	traits::SignedBlock,
	types::{BlockHash, SignedBlock as SignedSidechainBlock},
};
use its_test::sidechain_block_builder::SidechainBlockBuilder;
use sp_core::{ed25519, Pair, H256};
use std::{
	assert_matches::assert_matches,
	time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn get_blocks_following_works_for_regular_case() {
	let block_1 = create_signed_block(1, BlockHash::default());
	let block_2 = create_signed_block(2, block_1.hash());
	let block_3 = create_signed_block(3, block_2.hash());
	let block_4 = create_signed_block(4, block_3.hash());

	let db_fixture = TestDbFixture::setup(
		"get_blocks_following_works_for_regular_case",
		vec![block_1.clone(), block_2.clone(), block_3.clone(), block_4.clone()],
	);

	{
		let updated_sidechain_db = db_fixture.get_handle();
		let blocks_following_1 = updated_sidechain_db
			.get_blocks_following(&block_1.hash(), &default_shard())
			.unwrap();

		assert_eq!(3, blocks_following_1.len());
		assert_eq!(block_2.hash(), blocks_following_1.first().unwrap().hash());
		assert_eq!(block_4.hash(), blocks_following_1.last().unwrap().hash());
	}
}

#[test]
fn get_blocks_follow_returns_empty_vec_if_block_not_found() {
	let block_1 = create_signed_block(1, BlockHash::random());

	let db_fixture = TestDbFixture::setup(
		"get_blocks_follow_returns_empty_vec_if_block_not_found",
		vec![block_1.clone()],
	);

	{
		let updated_sidechain_db = db_fixture.get_handle();
		let block_hash_to_be_followed = BlockHash::from_low_u64_be(1);
		assert_ne!(block_1.hash(), block_hash_to_be_followed); // Off-chance that random() generates exactly the same hash

		assert_eq!(
			updated_sidechain_db
				.get_blocks_following(&block_hash_to_be_followed, &default_shard())
				.unwrap(),
			Vec::new()
		);
	}
}

#[test]
fn get_blocks_returns_none_if_last_is_already_most_recent_block() {
	let block_1 = create_signed_block(1, BlockHash::random());

	let db_fixture = TestDbFixture::setup(
		"get_blocks_returns_none_if_last_is_already_most_recent_block",
		vec![block_1.clone()],
	);

	{
		let updated_sidechain_db = db_fixture.get_handle();

		assert_eq!(
			updated_sidechain_db
				.get_blocks_following(&block_1.hash(), &default_shard())
				.unwrap(),
			Vec::new()
		);
	}
}

#[test]
fn given_block_with_invalid_ancestry_returns_error() {
	let block_1 = create_signed_block(1, BlockHash::default());
	let block_2 = create_signed_block(2, BlockHash::random()); // Should be block_1 hash, but be deliberately introduce an invalid parent hash.

	let db_fixture = TestDbFixture::setup(
		"given_block_with_invalid_ancestry_returns_error",
		vec![block_1.clone(), block_2.clone()],
	);

	{
		let updated_sidechain_db = db_fixture.get_handle();

		assert_matches!(
			updated_sidechain_db.get_blocks_following(&block_1.hash(), &default_shard()),
			Err(Error::FailedToFindParentBlock)
		);
	}
}

fn default_shard() -> ShardIdentifier {
	ShardIdentifier::default()
}

fn create_signed_block(block_number: u64, parent_hash: BlockHash) -> SignedSidechainBlock {
	SidechainBlockBuilder::default()
		.with_signer(ed25519::Pair::from_string("//Alice", None).unwrap())
		.with_parent_hash(parent_hash)
		.with_parentchain_block_hash(H256::random())
		.with_timestamp(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64)
		.with_shard(default_shard())
		.with_number(block_number)
		.build_signed()
}
