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

use crate::{
	test::{
		fixtures::initialize_test_state::init_state,
		mocks::{
			propose_to_import_call_mock::ProposeToImportOCallApi,
			types::{
				TestBlockComposer, TestBlockImporter, TestOCallApi, TestRpcAuthor,
				TestRpcResponder, TestShieldingKey, TestSidechainDb, TestSigner, TestStateHandler,
				TestStateKey, TestStfExecutor, TestTopPool, TestTopPoolExecutor,
			},
		},
	},
	top_pool_execution::{exec_aura_on_slot, send_blocks_and_extrinsics},
};
use codec::Encode;
use ita_stf::{
	test_genesis::{endowed_account, unendowed_account, second_endowed_account},
	KeyPair, TrustedCall, TrustedOperation,
};
use itc_parentchain::light_client::mocks::validator_access_mock::ValidatorAccessMock;
use itp_extrinsics_factory::mock::ExtrinsicsFactoryMock;
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_settings::sidechain::SLOT_DURATION;
use itp_sgx_crypto::ShieldingCrypto;
use itp_stf_state_handler::handle_state::HandleState;
use itp_test::{
	builders::parentchain_header_builder::ParentchainHeaderBuilder,
	mock::handle_state_mock::HandleStateMock,
};
use itp_time_utils::duration_now;
use itp_types::{Block as ParentchainBlock, Enclave, ShardIdentifier};
use its_sidechain::{
	aura::proposer_factory::ProposerFactory,
	primitives::types::SignedBlock as SignedSidechainBlock,
	slots::{slot_from_time_stamp_and_duration, SlotInfo},
	state::SidechainState,
	top_pool::pool::Options as PoolOptions,
	top_pool_rpc_author::{api::SidechainApi, author::AuthorTopFilter, traits::AuthorApi},
};
use jsonrpc_core::futures::executor;
use log::*;
use primitive_types::H256;
use sgx_crypto_helper::RsaKeyPair;
use sp_core::Pair;
use std::{sync::Arc, vec, vec::Vec};

pub fn produce_sidechain_block_and_import_it() {
	let _ = env_logger::builder().is_test(true).try_init();
	info!("Setting up test.");

	let signer = TestSigner::from_seed(b"42315678901234567890123456789012");
	let shielding_key = TestShieldingKey::new().unwrap();
	let state_key = TestStateKey::new([3u8; 16], [1u8; 16]);

	let ocall_api = create_ocall_api(&signer);

	info!("Initializing state and shard..");
	let state_handler = Arc::new(TestStateHandler::default());
	let (_, shard_id) = init_state(state_handler.as_ref());
	let shards = vec![shard_id];

	let stf_executor = Arc::new(TestStfExecutor::new(ocall_api.clone(), state_handler.clone()));
	let top_pool = create_top_pool();

	let rpc_author = Arc::new(TestRpcAuthor::new(
		top_pool,
		AuthorTopFilter {},
		state_handler.clone(),
		shielding_key,
	));
	let top_pool_operation_handler =
		Arc::new(TestTopPoolExecutor::new(rpc_author.clone(), stf_executor.clone()));
	let block_importer = Arc::new(TestBlockImporter::new(
		state_handler.clone(),
		state_key,
		signer.clone(),
		top_pool_operation_handler.clone(),
		ocall_api.clone(),
	));
	let block_composer =
		Arc::new(TestBlockComposer::new(signer.clone(), state_key, rpc_author.clone()));
	let proposer_environment =
		ProposerFactory::new(top_pool_operation_handler, stf_executor.clone(), block_composer);
	let extrinsics_factory = ExtrinsicsFactoryMock::default();
	let validator_access = ValidatorAccessMock::default();

	info!("Create trusted operations..");
	let trusted_operation =
		encrypted_trusted_operation_transfer_balance(ocall_api.as_ref(), &shard_id, &shielding_key);
	let invalid_trusted_operation =
		invalid_encrypted_trusted_operation_transfer_balance(ocall_api.as_ref(), &shard_id, &shielding_key);
	info!("Add trusted operations to TOP pool..");
	let author_submit_future = async { rpc_author.submit_top(trusted_operation, shard_id).await };
	executor::block_on(author_submit_future).unwrap();
	let author_submit_future = async { rpc_author.submit_top(invalid_trusted_operation, shard_id).await };
	executor::block_on(author_submit_future).unwrap();

	// Ensure we have exactly two trusted calls in our TOP pool, and no getters.
	assert_eq!(2, rpc_author.get_pending_tops_separated(shard_id).unwrap().0.len());
	assert!(rpc_author.get_pending_tops_separated(shard_id).unwrap().1.is_empty());

	info!("Setup AURA SlotInfo");
	let parentchain_header = ParentchainHeaderBuilder::default().build();
	let timestamp = duration_now();
	let slot = slot_from_time_stamp_and_duration(duration_now(), SLOT_DURATION);
	let slot_info = SlotInfo::new(slot, timestamp, SLOT_DURATION, parentchain_header.clone());

	info!("Test setup is done.");

	let state_hash_before_block_production = get_state_hash(state_handler.as_ref(), &shard_id);

	info!("Executing AURA on slot..");
	let (blocks, opaque_calls) =
		exec_aura_on_slot::<_, ParentchainBlock, SignedSidechainBlock, _, _>(
			slot_info,
			signer,
			ocall_api.as_ref().clone(),
			proposer_environment,
			shards,
		)
		.unwrap();

	assert_eq!(1, blocks.len());
	assert_eq!(
		state_hash_before_block_production,
		get_state_hash(state_handler.as_ref(), &shard_id)
	);

	// Ensure that only invalid calls are removed from pool. Valid calls should only be removed upon block import.
	//assert_eq!(1, rpc_author.get_pending_tops_separated(shard_id).unwrap().0.len());

	info!("Executed AURA successfully. Sending blocks and extrinsics..");
	let propose_to_block_import_ocall_api =
		ProposeToImportOCallApi::new(parentchain_header, block_importer);

	send_blocks_and_extrinsics::<ParentchainBlock, _, _, _, _>(
		blocks,
		opaque_calls,
		propose_to_block_import_ocall_api,
		&validator_access,
		&extrinsics_factory,
	)
	.unwrap();

	// After importing the sidechain block, the trusted operation should be removed.
	assert!(rpc_author.get_pending_tops_separated(shard_id).unwrap().0.is_empty());

	// After importing the block, the state hash must be changed.
	assert_ne!(
		state_hash_before_block_production,
		get_state_hash(state_handler.as_ref(), &shard_id)
	);
}

fn encrypted_trusted_operation_transfer_balance<
	AttestationApi: EnclaveAttestationOCallApi,
	ShieldingKey: ShieldingCrypto,
>(
	attestation_api: &AttestationApi,
	shard_id: &ShardIdentifier,
	shielding_key: &ShieldingKey,
) -> Vec<u8> {
	let from_account = endowed_account();
	let to_account = unendowed_account();
	let mr_enclave = attestation_api.get_mrenclave_of_self().unwrap();

	let call = TrustedCall::balance_transfer(
		from_account.public().into(),
		to_account.public().into(),
		1000,
	)
	.sign(&KeyPair::Ed25519(from_account), 0, &mr_enclave.m, shard_id);

	let trusted_operation = TrustedOperation::direct_call(call);
	let encoded_operation = trusted_operation.encode();

	shielding_key.encrypt(encoded_operation.as_slice()).unwrap()
}

fn invalid_encrypted_trusted_operation_transfer_balance<
	AttestationApi: EnclaveAttestationOCallApi,
	ShieldingKey: ShieldingCrypto,
>(
	attestation_api: &AttestationApi,
	shard_id: &ShardIdentifier,
	shielding_key: &ShieldingKey,
) -> Vec<u8> {
	let from_account = second_endowed_account();
	let to_account = unendowed_account();
	let mr_enclave = attestation_api.get_mrenclave_of_self().unwrap();

	let call = TrustedCall::balance_transfer(
		from_account.public().into(),
		to_account.public().into(),
		20000,
	)
	.sign(&KeyPair::Ed25519(from_account), 0, &mr_enclave.m, shard_id);

	let trusted_operation = TrustedOperation::direct_call(call);
	let encoded_operation = trusted_operation.encode();

	shielding_key.encrypt(encoded_operation.as_slice()).unwrap()
}

fn get_state_hash(state_handler: &HandleStateMock, shard_id: &ShardIdentifier) -> H256 {
	let state = state_handler.load_initialized(shard_id).unwrap();
	let sidechain_state = TestSidechainDb::new(state);
	sidechain_state.state_hash()
}

fn create_top_pool() -> Arc<TestTopPool> {
	let rpc_responder = Arc::new(TestRpcResponder::new());
	let side_chain_api = Arc::new(SidechainApi::<ParentchainBlock>::new());
	Arc::new(TestTopPool::create(PoolOptions::default(), side_chain_api, rpc_responder))
}

fn create_ocall_api(signer: &TestSigner) -> Arc<TestOCallApi> {
	let enclave_validateer = Enclave::new(
		signer.public().into(),
		Default::default(),
		Default::default(),
		Default::default(),
	);
	Arc::new(TestOCallApi::default().with_validateer_set(Some(vec![enclave_validateer])))
}
