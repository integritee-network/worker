/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

//! Type definitions for testing. Includes various mocks.

use crate::test::mocks::rpc_responder_mock::RpcResponderMock;
use itc_parentchain::block_import_dispatcher::trigger_parentchain_block_import_mock::TriggerParentchainBlockImportMock;
use itp_node_api::metadata::{metadata_mocks::NodeMetadataMock, provider::NodeMetadataRepository};
use itp_sgx_crypto::{mocks::KeyRepositoryMock, Aes};
use itp_sgx_externalities::SgxExternalities;
use itp_stf_executor::executor::StfExecutor;
use itp_test::mock::{
	handle_state_mock::HandleStateMock, metrics_ocall_mock::MetricsOCallMock,
	onchain_mock::OnchainMock,
};
use itp_top_pool::basic_pool::BasicPool;
use itp_top_pool_author::{
	api::SidechainApi,
	author::{Author, AuthorTopFilter},
};
use itp_types::{Block as ParentchainBlock, SignedBlock as SignedParentchainBlock};
use its_sidechain::{
	aura::block_importer::BlockImporter, block_composer::BlockComposer, state::SidechainDB,
	top_pool_executor::TopPoolOperationHandler,
};
use primitive_types::H256;
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;
use sidechain_primitives::types::{Block as SidechainBlock, SignedBlock as SignedSidechainBlock};
use sp_core::ed25519 as spEd25519;

pub type TestSigner = spEd25519::Pair;
pub type TestShieldingKey = Rsa3072KeyPair;
pub type TestStateKey = Aes;

pub type TestShieldingKeyRepo = KeyRepositoryMock<TestShieldingKey>;

pub type TestStateKeyRepo = KeyRepositoryMock<TestStateKey>;

pub type TestStateHandler = HandleStateMock;

pub type TestSidechainDb = SidechainDB<SidechainBlock, SgxExternalities>;

pub type TestOCallApi = OnchainMock;

pub type TestParentchainBlockImportTrigger =
	TriggerParentchainBlockImportMock<SignedParentchainBlock>;

pub type TestNodeMetadataRepository = NodeMetadataRepository<NodeMetadataMock>;

pub type TestStfExecutor = StfExecutor<TestOCallApi, TestStateHandler, TestNodeMetadataRepository>;

pub type TestRpcResponder = RpcResponderMock<H256>;

pub type TestTopPool =
	BasicPool<SidechainApi<ParentchainBlock>, ParentchainBlock, TestRpcResponder>;

pub type TestTopPoolAuthor =
	Author<TestTopPool, AuthorTopFilter, TestStateHandler, TestShieldingKeyRepo, MetricsOCallMock>;

pub type TestTopPoolExecutor = TopPoolOperationHandler<
	ParentchainBlock,
	SignedSidechainBlock,
	TestTopPoolAuthor,
	TestStfExecutor,
>;

pub type TestBlockComposer = BlockComposer<
	ParentchainBlock,
	SignedSidechainBlock,
	TestSigner,
	TestStateKeyRepo,
	TestNodeMetadataRepository,
>;

pub type TestBlockImporter = BlockImporter<
	TestSigner,
	ParentchainBlock,
	SignedSidechainBlock,
	TestOCallApi,
	TestSidechainDb,
	HandleStateMock,
	TestStateKeyRepo,
	TestTopPoolExecutor,
	TestParentchainBlockImportTrigger,
>;
