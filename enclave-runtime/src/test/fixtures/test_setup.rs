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
	ocall::OcallApi,
	test::{
		fixtures::initialize_test_state::init_state, mocks::rpc_responder_mock::RpcResponderMock,
	},
};
use ita_sgx_runtime::Runtime;
use ita_stf::{Getter, State, Stf, TrustedCallSigned};
use itp_node_api::metadata::{metadata_mocks::NodeMetadataMock, provider::NodeMetadataRepository};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_sgx_crypto::{ed25519_derivation::DeriveEd25519, mocks::KeyRepositoryMock};
use itp_sgx_externalities::SgxExternalities;
use itp_stf_executor::executor::StfExecutor;
use itp_stf_primitives::types::ShardIdentifier;
use itp_test::mock::{
	handle_state_mock::HandleStateMock, metrics_ocall_mock::MetricsOCallMock,
	shielding_crypto_mock::ShieldingCryptoMock,
};
use itp_top_pool::{basic_pool::BasicPool, pool::ExtrinsicHash};
use itp_top_pool_author::{api::SidechainApi, author::Author, top_filter::AllowAllTopsFilter};
use itp_types::{Block, MrEnclave};
use sp_core::{crypto::Pair, ed25519 as spEd25519};
use std::sync::Arc;

pub type TestRpcResponder = RpcResponderMock<ExtrinsicHash<SidechainApi<Block>>>;
pub type TestTopPool = BasicPool<SidechainApi<Block>, Block, TestRpcResponder>;
pub type TestShieldingKeyRepo = KeyRepositoryMock<ShieldingCryptoMock>;
pub type TestTopPoolAuthor = Author<
	TestTopPool,
	AllowAllTopsFilter,
	HandleStateMock,
	TestShieldingKeyRepo,
	MetricsOCallMock,
>;
pub type TestStf = Stf<TrustedCallSigned, Getter, SgxExternalities, Runtime>;

pub type TestStfExecutor =
	StfExecutor<OcallApi, HandleStateMock, NodeMetadataRepository<NodeMetadataMock>, TestStf>;

/// Returns all the things that are commonly used in tests and runs
/// `ensure_no_empty_shard_directory_exists`
pub fn test_setup() -> (
	Arc<TestTopPoolAuthor>,
	State,
	ShardIdentifier,
	MrEnclave,
	ShieldingCryptoMock,
	Arc<HandleStateMock>,
	Arc<TestStfExecutor>,
) {
	let shielding_key = ShieldingCryptoMock::default();
	let shielding_key_repo = Arc::new(KeyRepositoryMock::new(shielding_key.clone()));

	let state_handler = Arc::new(HandleStateMock::default());
	let (state, shard) =
		init_state(state_handler.as_ref(), enclave_call_signer(&shielding_key).public().into());
	let top_pool = test_top_pool();
	let mrenclave = OcallApi.get_mrenclave_of_self().unwrap().m;

	let node_metadata_repo = Arc::new(NodeMetadataRepository::new(NodeMetadataMock::new()));
	let stf_executor = Arc::new(TestStfExecutor::new(
		Arc::new(OcallApi),
		state_handler.clone(),
		node_metadata_repo,
	));

	(
		Arc::new(TestTopPoolAuthor::new(
			Arc::new(top_pool),
			AllowAllTopsFilter,
			state_handler.clone(),
			shielding_key_repo,
			Arc::new(MetricsOCallMock::default()),
		)),
		state,
		shard,
		mrenclave,
		shielding_key,
		state_handler,
		stf_executor,
	)
}

pub fn test_top_pool() -> TestTopPool {
	let chain_api = Arc::new(SidechainApi::<Block>::new());
	let top_pool =
		BasicPool::create(Default::default(), chain_api, Arc::new(TestRpcResponder::new()));

	top_pool
}

pub fn enclave_call_signer<Source: DeriveEd25519>(key_source: &Source) -> spEd25519::Pair {
	key_source.derive_ed25519().unwrap()
}
