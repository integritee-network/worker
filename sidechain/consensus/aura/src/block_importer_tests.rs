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

use crate::block_importer::BlockImporter;
use itp_sgx_crypto::aes::Aes;
use itp_test::mock::{handle_state_mock::HandleStateMock, onchain_mock::OnchainMock};
use itp_types::Block as ParentchainBlock;
use its_primitives::types::{Block as SidechainBlock, SignedBlock as SignedSidechainBlock};
use its_state::SidechainDB;
use its_top_pool_executor::call_operator_mock::TopPoolCallOperatorMock;
use sgx_externalities::SgxExternalities;
use sp_core::ed25519::Pair;
use std::sync::Arc;

type TestSidechainState = SidechainDB<SidechainBlock, SgxExternalities>;
type TestTopPoolCallOperator = TopPoolCallOperatorMock<ParentchainBlock, SignedSidechainBlock>;
type TestBlockImporter = BlockImporter<
	Pair,
	ParentchainBlock,
	SignedSidechainBlock,
	OnchainMock,
	TestSidechainState,
	HandleStateMock,
	Aes,
	TestTopPoolCallOperator,
>;

fn state_key() -> Aes {
	Aes::new([3u8; 16], [0u8; 16])
}

fn test_fixtures() -> (TestBlockImporter, Arc<HandleStateMock>, Arc<TestTopPoolCallOperator>) {
	let state_handler = Arc::new(HandleStateMock::default());
	let state_key = state_key();
	let top_pool_call_operator = Arc::new(TestTopPoolCallOperator::default());
	let ocall_api = Arc::new(OnchainMock::default());

	let block_importer = TestBlockImporter::new(
		state_handler.clone(),
		state_key,
		top_pool_call_operator.clone(),
		ocall_api,
	);

	(block_importer, state_handler, top_pool_call_operator)
}

#[test]
fn simple_block_import_works() {
	let (_block_importer, _state_handler, _top_pool_call_operator) = test_fixtures();

	//block_importer.import_block()
}
