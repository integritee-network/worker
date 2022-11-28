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

use crate::{block_importer::BlockImporter, test::fixtures::validateer, ShardIdentifierFor};
use codec::Encode;
use core::assert_matches::assert_matches;
use itc_parentchain_block_import_dispatcher::trigger_parentchain_block_import_mock::TriggerParentchainBlockImportMock;
use itc_parentchain_test::{
	parentchain_block_builder::ParentchainBlockBuilder,
	parentchain_header_builder::ParentchainHeaderBuilder,
};
use itp_sgx_crypto::{aes::Aes, mocks::KeyRepositoryMock, StateCrypto};
use itp_sgx_externalities::SgxExternalitiesDiffType;
use itp_stf_state_handler::handle_state::HandleState;
use itp_test::mock::{handle_state_mock::HandleStateMock, onchain_mock::OnchainMock};
use itp_time_utils::{duration_now, now_as_millis};
use itp_top_pool_author::mocks::AuthorApiMock;
use itp_types::{Block as ParentchainBlock, Header as ParentchainHeader, H256};
use its_consensus_common::{BlockImport, Error as ConsensusError};
use its_primitives::{
	traits::{SignBlock, SignedBlock},
	types::SignedBlock as SignedSidechainBlock,
};
use its_state::StateUpdate;
use its_test::{
	sidechain_block_builder::SidechainBlockBuilder,
	sidechain_block_data_builder::SidechainBlockDataBuilder,
	sidechain_header_builder::SidechainHeaderBuilder,
};
use sp_core::{blake2_256, ed25519::Pair};
use sp_keyring::ed25519::Keyring;
use sp_runtime::generic::SignedBlock as SignedParentchainBlock;
use std::sync::Arc;

type TestTopPoolAuthor = AuthorApiMock<H256, H256>;
type TestParentchainBlockImportTrigger =
	TriggerParentchainBlockImportMock<SignedParentchainBlock<ParentchainBlock>>;
type TestStateKeyRepo = KeyRepositoryMock<Aes>;
type TestBlockImporter = BlockImporter<
	Pair,
	ParentchainBlock,
	SignedSidechainBlock,
	OnchainMock,
	HandleStateMock,
	TestStateKeyRepo,
	TestTopPoolAuthor,
	TestParentchainBlockImportTrigger,
>;

fn state_key() -> Aes {
	Aes::new([3u8; 16], [0u8; 16])
}

fn shard() -> ShardIdentifierFor<SignedSidechainBlock> {
	blake2_256(&[1, 2, 3, 4, 5, 6]).into()
}

fn default_authority() -> Pair {
	Keyring::Alice.pair()
}

fn test_fixtures(
	parentchain_header: &ParentchainHeader,
	parentchain_block_import_trigger: Arc<TestParentchainBlockImportTrigger>,
) -> (TestBlockImporter, Arc<HandleStateMock>, Arc<TestTopPoolAuthor>) {
	let state_handler = Arc::new(HandleStateMock::from_shard(shard()).unwrap());
	let top_pool_author = Arc::new(TestTopPoolAuthor::default());
	let ocall_api = Arc::new(OnchainMock::default().add_validateer_set(
		parentchain_header,
		Some(vec![validateer(Keyring::Alice.public().into())]),
	));
	let state_key_repository = Arc::new(TestStateKeyRepo::new(state_key()));

	let block_importer = TestBlockImporter::new(
		state_handler.clone(),
		state_key_repository,
		top_pool_author.clone(),
		parentchain_block_import_trigger,
		ocall_api,
	);

	(block_importer, state_handler, top_pool_author)
}

fn test_fixtures_with_default_import_trigger(
	parentchain_header: &ParentchainHeader,
) -> (TestBlockImporter, Arc<HandleStateMock>, Arc<TestTopPoolAuthor>) {
	test_fixtures(parentchain_header, Arc::new(TestParentchainBlockImportTrigger::default()))
}

fn empty_encrypted_state_update(state_handler: &HandleStateMock) -> Vec<u8> {
	let (_, apriori_state_hash) = state_handler.load_cloned(&shard()).unwrap();
	let empty_state_diff = SgxExternalitiesDiffType::default();
	let mut state_update =
		StateUpdate::new(apriori_state_hash, apriori_state_hash, empty_state_diff).encode();
	state_key().encrypt(&mut state_update).unwrap();
	state_update
}

fn signed_block(
	parentchain_header: &ParentchainHeader,
	state_handler: &HandleStateMock,
	signer: Pair,
) -> SignedSidechainBlock {
	let state_update = empty_encrypted_state_update(state_handler);

	let header = SidechainHeaderBuilder::default()
		.with_parent_hash(H256::default())
		.with_shard(shard())
		.build();

	let block_data = SidechainBlockDataBuilder::default()
		.with_timestamp(now_as_millis())
		.with_layer_one_head(parentchain_header.hash())
		.with_signer(signer.clone())
		.with_payload(state_update)
		.build();

	SidechainBlockBuilder::default()
		.with_header(header)
		.with_block_data(block_data)
		.with_signer(signer)
		.build_signed()
}

fn default_authority_signed_block(
	parentchain_header: &ParentchainHeader,
	state_handler: &HandleStateMock,
) -> SignedSidechainBlock {
	signed_block(parentchain_header, state_handler, default_authority())
}

#[test]
fn simple_block_import_works() {
	let parentchain_header = ParentchainHeaderBuilder::default().build();
	let (block_importer, state_handler, _) =
		test_fixtures_with_default_import_trigger(&parentchain_header);
	let signed_sidechain_block =
		default_authority_signed_block(&parentchain_header, state_handler.as_ref());

	block_importer
		.import_block(signed_sidechain_block, &parentchain_header)
		.unwrap();
}

#[test]
fn block_import_with_invalid_signature_fails() {
	let parentchain_header = ParentchainHeaderBuilder::default().build();
	let (block_importer, state_handler, _) =
		test_fixtures_with_default_import_trigger(&parentchain_header);

	let state_update = empty_encrypted_state_update(state_handler.as_ref());

	let header = SidechainHeaderBuilder::default()
		.with_parent_hash(H256::default())
		.with_shard(shard())
		.build();

	let block_data = SidechainBlockDataBuilder::default()
		.with_timestamp(duration_now().as_millis() as u64)
		.with_layer_one_head(parentchain_header.hash())
		.with_signer(Keyring::Charlie.pair())
		.with_payload(state_update)
		.build();

	let block = SidechainBlockBuilder::default()
		.with_signer(Keyring::Charlie.pair())
		.with_header(header)
		.with_block_data(block_data)
		.build();

	// Bob signs the block, but Charlie is set as the author -> invalid signature.
	let invalid_signature_block: SignedSidechainBlock = block.sign_block(&Keyring::Bob.pair());

	assert!(!invalid_signature_block.verify_signature());
	assert!(block_importer
		.import_block(invalid_signature_block, &parentchain_header)
		.is_err());
}

#[test]
fn block_import_with_invalid_parentchain_block_fails() {
	let parentchain_header_invalid = ParentchainHeaderBuilder::default().with_number(2).build();
	let parentchain_header = ParentchainHeaderBuilder::default().with_number(10).build();
	let (block_importer, state_handler, _) =
		test_fixtures_with_default_import_trigger(&parentchain_header);

	let signed_sidechain_block =
		default_authority_signed_block(&parentchain_header_invalid, state_handler.as_ref());

	assert!(block_importer
		.import_block(signed_sidechain_block, &parentchain_header)
		.is_err());
}

#[test]
fn cleanup_removes_tops_from_pool() {
	let parentchain_header = ParentchainHeaderBuilder::default().build();
	let (block_importer, state_handler, top_pool_author) =
		test_fixtures_with_default_import_trigger(&parentchain_header);
	let signed_sidechain_block =
		default_authority_signed_block(&parentchain_header, state_handler.as_ref());
	let bob_signed_sidechain_block =
		signed_block(&parentchain_header, state_handler.as_ref(), Keyring::Bob.pair());

	block_importer.cleanup(&signed_sidechain_block).unwrap();
	block_importer.cleanup(&bob_signed_sidechain_block).unwrap();

	assert_eq!(2, *top_pool_author.remove_attempts.read().unwrap());
}

#[test]
fn sidechain_block_import_triggers_parentchain_block_import() {
	let previous_parentchain_header = ParentchainHeaderBuilder::default().with_number(4).build();
	let latest_parentchain_header = ParentchainHeaderBuilder::default()
		.with_number(5)
		.with_parent_hash(previous_parentchain_header.hash())
		.build();

	let latest_parentchain_block = ParentchainBlockBuilder::default()
		.with_header(latest_parentchain_header.clone())
		.build_signed();

	let parentchain_block_import_trigger = Arc::new(
		TestParentchainBlockImportTrigger::default()
			.with_latest_imported(Some(latest_parentchain_block)),
	);
	let (block_importer, state_handler, _) =
		test_fixtures(&latest_parentchain_header, parentchain_block_import_trigger.clone());

	let signed_sidechain_block =
		default_authority_signed_block(&latest_parentchain_header, state_handler.as_ref());

	block_importer
		.import_block(signed_sidechain_block, &previous_parentchain_header)
		.unwrap();

	assert!(parentchain_block_import_trigger.has_import_been_called());
}

#[test]
fn peek_parentchain_block_finds_block_in_queue() {
	let previous_parentchain_header = ParentchainHeaderBuilder::default().with_number(4).build();
	let latest_parentchain_header = ParentchainHeaderBuilder::default()
		.with_number(5)
		.with_parent_hash(previous_parentchain_header.hash())
		.build();

	let latest_parentchain_block = ParentchainBlockBuilder::default()
		.with_header(latest_parentchain_header.clone())
		.build_signed();

	let parentchain_block_import_trigger = Arc::new(
		TestParentchainBlockImportTrigger::default()
			.with_latest_imported(Some(latest_parentchain_block)),
	);

	let (block_importer, state_handler, _) =
		test_fixtures(&latest_parentchain_header, parentchain_block_import_trigger);

	let signed_sidechain_block =
		default_authority_signed_block(&latest_parentchain_header, state_handler.as_ref());

	let peeked_header = block_importer
		.peek_parentchain_header(&signed_sidechain_block.block, &previous_parentchain_header)
		.unwrap();

	assert_eq!(peeked_header, latest_parentchain_header);
}

#[test]
fn peek_parentchain_block_returns_error_if_no_corresponding_block_can_be_found() {
	let previous_parentchain_header = ParentchainHeaderBuilder::default().with_number(1).build();
	let latest_parentchain_header = ParentchainHeaderBuilder::default()
		.with_number(2)
		.with_parent_hash(previous_parentchain_header.hash())
		.build();

	let parentchain_block_import_trigger = Arc::new(
		TestParentchainBlockImportTrigger::default(), // Parentchain block import queue is empty, so nothing will be found when peeked.
	);

	let (block_importer, state_handler, _) =
		test_fixtures(&latest_parentchain_header, parentchain_block_import_trigger);

	let signed_sidechain_block =
		default_authority_signed_block(&latest_parentchain_header, state_handler.as_ref());

	let peek_result = block_importer
		.peek_parentchain_header(&signed_sidechain_block.block, &previous_parentchain_header);

	assert_matches!(peek_result, Err(ConsensusError::Other(_)));
}
