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
		fixtures::{
			components::{
				create_ocall_api, create_top_pool, encrypt_trusted_operation, sign_trusted_call,
			},
			initialize_test_state::init_state,
			test_setup::{enclave_call_signer, TestStf},
		},
		mocks::{propose_to_import_call_mock::ProposeToImportOCallApi, types::*},
	},
	top_pool_execution::{exec_aura_on_slot, send_blocks_and_extrinsics},
};
use codec::Decode;
use ita_stf::{
	test_genesis::{endowed_account, second_endowed_account, unendowed_account},
	Balance, StatePayload, TrustedCall, TrustedOperation,
};
use itc_parentchain::light_client::mocks::validator_access_mock::ValidatorAccessMock;
use itc_parentchain_test::parentchain_header_builder::ParentchainHeaderBuilder;
use itp_extrinsics_factory::mock::ExtrinsicsFactoryMock;
use itp_node_api::metadata::{metadata_mocks::NodeMetadataMock, provider::NodeMetadataRepository};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_settings::{
	sidechain::SLOT_DURATION,
	worker_mode::{ProvideWorkerMode, WorkerMode, WorkerModeProvider},
};
use itp_sgx_crypto::{Aes, ShieldingCryptoEncrypt, StateCrypto};
use itp_sgx_externalities::SgxExternalitiesDiffType;
use itp_stf_interface::system_pallet::{SystemPalletAccountInterface, SystemPalletEventInterface};
use itp_stf_state_handler::handle_state::HandleState;
use itp_test::mock::{handle_state_mock::HandleStateMock, metrics_ocall_mock::MetricsOCallMock};
use itp_time_utils::duration_now;
use itp_top_pool_author::{top_filter::AllowAllTopsFilter, traits::AuthorApi};
use itp_types::{AccountId, Block as ParentchainBlock, ShardIdentifier};
use its_block_verification::slot::slot_from_timestamp_and_duration;
use its_primitives::{traits::Block, types::SignedBlock as SignedSidechainBlock};
use its_sidechain::{aura::proposer_factory::ProposerFactory, slots::SlotInfo};
use jsonrpc_core::futures::executor;
use log::*;
use primitive_types::H256;
use sgx_crypto_helper::RsaKeyPair;
use sp_core::{ed25519, Pair};
use std::{sync::Arc, vec, vec::Vec};

/// Integration test for sidechain block production and block import.
/// (requires Sidechain mode)
///
/// - Create trusted calls and add them to the TOP pool.
/// - Run AURA on a valid and claimed slot, which executes the trusted operations and produces a new block.
/// - Import the new sidechain block, which updates the state.
pub fn produce_sidechain_block_and_import_it() {
	// Test can only be run in Sidechain mode
	if WorkerModeProvider::worker_mode() != WorkerMode::Sidechain {
		info!("Ignoring sidechain block production test: Not in sidechain mode");
		return
	}

	let _ = env_logger::builder().is_test(true).try_init();
	info!("Setting up test.");

	let signer = TestSigner::from_seed(b"42315678901234567890123456789012");
	let shielding_key = TestShieldingKey::new().unwrap();
	let state_key = TestStateKey::new([3u8; 16], [1u8; 16]);
	let shielding_key_repo = Arc::new(TestShieldingKeyRepo::new(shielding_key));
	let state_key_repo = Arc::new(TestStateKeyRepo::new(state_key));
	let parentchain_header = ParentchainHeaderBuilder::default().build();

	let ocall_api = create_ocall_api(&parentchain_header, &signer);

	info!("Initializing state and shard..");
	let state_handler = Arc::new(TestStateHandler::default());
	let enclave_call_signer = enclave_call_signer(&shielding_key);
	let (_, shard_id) = init_state(state_handler.as_ref(), enclave_call_signer.public().into());
	let shards = vec![shard_id];

	let node_metadata_repo = Arc::new(NodeMetadataRepository::new(NodeMetadataMock::new()));
	let stf_executor = Arc::new(TestStfExecutor::new(
		ocall_api.clone(),
		state_handler.clone(),
		node_metadata_repo.clone(),
	));
	let top_pool = create_top_pool();

	let top_pool_author = Arc::new(TestTopPoolAuthor::new(
		top_pool,
		AllowAllTopsFilter {},
		state_handler.clone(),
		shielding_key_repo,
		Arc::new(MetricsOCallMock::default()),
	));
	let parentchain_block_import_trigger = Arc::new(TestParentchainBlockImportTrigger::default());
	let block_importer = Arc::new(TestBlockImporter::new(
		state_handler.clone(),
		state_key_repo.clone(),
		top_pool_author.clone(),
		parentchain_block_import_trigger.clone(),
		ocall_api.clone(),
	));
	let block_composer = Arc::new(TestBlockComposer::new(signer.clone(), state_key_repo.clone()));
	let proposer_environment =
		ProposerFactory::new(top_pool_author.clone(), stf_executor.clone(), block_composer);
	let extrinsics_factory = ExtrinsicsFactoryMock::default();
	let validator_access = ValidatorAccessMock::default();

	info!("Create trusted operations..");
	let sender = endowed_account();
	let sender_with_low_balance = second_endowed_account();
	let receiver = unendowed_account();
	let transfered_amount: Balance = 1000;
	let trusted_operation = encrypted_trusted_operation_transfer_balance(
		ocall_api.as_ref(),
		&shard_id,
		&shielding_key,
		sender,
		receiver.public().into(),
		transfered_amount,
	);
	let invalid_trusted_operation = encrypted_trusted_operation_transfer_balance(
		ocall_api.as_ref(),
		&shard_id,
		&shielding_key,
		sender_with_low_balance,
		receiver.public().into(),
		200000,
	);
	info!("Add trusted operations to TOP pool..");
	executor::block_on(top_pool_author.submit_top(trusted_operation, shard_id)).unwrap();
	executor::block_on(top_pool_author.submit_top(invalid_trusted_operation, shard_id)).unwrap();

	// Ensure we have exactly two trusted calls in our TOP pool, and no getters.
	assert_eq!(2, top_pool_author.get_pending_trusted_calls(shard_id).len());
	assert!(top_pool_author.get_pending_trusted_getters(shard_id).is_empty());

	info!("Setup AURA SlotInfo");
	let timestamp = duration_now();
	let slot = slot_from_timestamp_and_duration(duration_now(), SLOT_DURATION);
	let ends_at = timestamp + SLOT_DURATION;
	let slot_info =
		SlotInfo::new(slot, timestamp, SLOT_DURATION, ends_at, parentchain_header.clone());

	info!("Test setup is done.");

	let state_hash_before_block_production = get_state_hash(state_handler.as_ref(), &shard_id);

	info!("Executing AURA on slot..");
	let (blocks, opaque_calls) =
		exec_aura_on_slot::<_, ParentchainBlock, SignedSidechainBlock, _, _, _>(
			slot_info,
			signer,
			ocall_api.clone(),
			parentchain_block_import_trigger.clone(),
			proposer_environment,
			shards,
		)
		.unwrap();

	assert_eq!(1, blocks.len());
	assert_eq!(
		state_hash_before_block_production,
		get_state_hash(state_handler.as_ref(), &shard_id)
	);

	let (apriori_state_hash_in_block, aposteriori_state_hash_in_block) =
		get_state_hashes_from_block(blocks.first().unwrap(), &state_key);
	assert_ne!(state_hash_before_block_production, aposteriori_state_hash_in_block);
	assert_eq!(state_hash_before_block_production, apriori_state_hash_in_block);

	// Ensure we have triggered the parentchain block import, because we claimed the slot.
	assert!(parentchain_block_import_trigger.has_import_been_called());

	// Ensure that invalid calls are removed from pool. Valid calls should only be removed upon block import.
	assert_eq!(1, top_pool_author.get_pending_trusted_calls(shard_id).len());

	info!("Executed AURA successfully. Sending blocks and extrinsics..");
	let propose_to_block_import_ocall_api =
		Arc::new(ProposeToImportOCallApi::new(parentchain_header, block_importer));

	send_blocks_and_extrinsics::<ParentchainBlock, _, _, _, _>(
		blocks,
		opaque_calls,
		propose_to_block_import_ocall_api,
		&validator_access,
		&extrinsics_factory,
	)
	.unwrap();

	// After importing the sidechain block, the trusted operation should be removed.
	assert!(top_pool_author.get_pending_trusted_calls(shard_id).is_empty());

	// After importing the block, the state hash must be changed.
	// We don't have a way to directly compare state hashes, because calculating the state hash
	// would also involve applying set_last_block action, which updates the state upon import.
	assert_ne!(
		state_hash_before_block_production,
		get_state_hash(state_handler.as_ref(), &shard_id)
	);

	let (mut state, _) = state_handler.load_cloned(&shard_id).unwrap();
	let free_balance = TestStf::get_account_data(&mut state, &receiver.public().into()).free;
	assert_eq!(free_balance, transfered_amount);
	assert!(TestStf::get_event_count(&mut state) > 0);
	assert!(TestStf::get_events(&mut state).len() > 0);
}

fn encrypted_trusted_operation_transfer_balance<
	AttestationApi: EnclaveAttestationOCallApi,
	ShieldingKey: ShieldingCryptoEncrypt,
>(
	attestation_api: &AttestationApi,
	shard_id: &ShardIdentifier,
	shielding_key: &ShieldingKey,
	from: ed25519::Pair,
	to: AccountId,
	amount: Balance,
) -> Vec<u8> {
	let call = TrustedCall::balance_transfer(from.public().into(), to, amount);
	let call_signed = sign_trusted_call(&call, attestation_api, shard_id, from);
	let trusted_operation = TrustedOperation::direct_call(call_signed);
	encrypt_trusted_operation(shielding_key, &trusted_operation)
}

fn get_state_hashes_from_block(
	signed_block: &SignedSidechainBlock,
	state_key: &Aes,
) -> (H256, H256) {
	let mut encrypted_state_diff = signed_block.block.block_data().encrypted_state_diff.clone();
	state_key.decrypt(&mut encrypted_state_diff).unwrap();
	let decoded_state =
		StatePayload::<SgxExternalitiesDiffType>::decode(&mut encrypted_state_diff.as_slice())
			.unwrap();
	(decoded_state.state_hash_apriori(), decoded_state.state_hash_aposteriori())
}

fn get_state_hash(state_handler: &HandleStateMock, shard_id: &ShardIdentifier) -> H256 {
	let (_, state_hash) = state_handler.load_cloned(shard_id).unwrap();
	state_hash
}
