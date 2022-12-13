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
			components::{create_ocall_api, create_top_pool},
			initialize_test_state::init_state,
			test_setup::{enclave_call_signer, TestStf},
		},
		mocks::{propose_to_import_call_mock::ProposeToImportOCallApi, types::*},
	},
	top_pool_execution::{exec_aura_on_slot, send_blocks_and_extrinsics},
};
use ita_sgx_runtime::Runtime;
use ita_stf::helpers::set_block_number;
use itc_parentchain::light_client::mocks::validator_access_mock::ValidatorAccessMock;
use itc_parentchain_test::parentchain_header_builder::ParentchainHeaderBuilder;
use itp_extrinsics_factory::mock::ExtrinsicsFactoryMock;
use itp_node_api::metadata::{metadata_mocks::NodeMetadataMock, provider::NodeMetadataRepository};
use itp_settings::{
	sidechain::SLOT_DURATION,
	worker_mode::{ProvideWorkerMode, WorkerMode, WorkerModeProvider},
};
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_interface::system_pallet::SystemPalletEventInterface;
use itp_stf_state_handler::handle_state::HandleState;
use itp_test::mock::metrics_ocall_mock::MetricsOCallMock;
use itp_time_utils::duration_now;
use itp_top_pool_author::top_filter::AllowAllTopsFilter;
use itp_types::Block as ParentchainBlock;
use its_block_verification::slot::slot_from_timestamp_and_duration;
use its_primitives::types::SignedBlock as SignedSidechainBlock;
use its_sidechain::{aura::proposer_factory::ProposerFactory, slots::SlotInfo};
use log::*;
use primitive_types::H256;
use sgx_crypto_helper::RsaKeyPair;
use sp_core::Pair;
use std::{sync::Arc, vec};

/// Integration test to ensure the events are reset upon block import.
/// Otherwise we will have an ever growing state.
/// (requires Sidechain mode)
pub fn ensure_events_get_reset_upon_block_proposal() {
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

	// Add some events to the state.
	let topic_hash = H256::from([7; 32]);
	let event = frame_system::Event::<Runtime>::CodeUpdated;
	let (lock, mut state) = state_handler.load_for_mutation(&shard_id).unwrap();
	state.execute_with(|| {
		set_block_number(10);
		frame_system::Pallet::<Runtime>::deposit_event_indexed(
			&[topic_hash],
			ita_sgx_runtime::RuntimeEvent::System(event),
		)
	});
	state_handler.write_after_mutation(state.clone(), lock, &shard_id).unwrap();

	// Check if state now really contains events and topics.
	let (mut state, _) = state_handler.load_cloned(&shard_id).unwrap();
	assert_eq!(TestStf::get_event_count(&mut state), 1);
	assert_eq!(TestStf::get_events(&mut state).len(), 1);
	assert_eq!(TestStf::get_event_topics(&mut state, &topic_hash).len(), 1);

	info!("Setup AURA SlotInfo");
	let timestamp = duration_now();
	let slot = slot_from_timestamp_and_duration(duration_now(), SLOT_DURATION);
	let ends_at = timestamp + SLOT_DURATION;
	let slot_info =
		SlotInfo::new(slot, timestamp, SLOT_DURATION, ends_at, parentchain_header.clone());

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

	// Ensure events have been reset.
	let (mut state, _) = state_handler.load_cloned(&shard_id).unwrap();
	assert_eq!(TestStf::get_event_count(&mut state), 0);
	assert_eq!(TestStf::get_event_topics(&mut state, &topic_hash).len(), 0);
	assert_eq!(TestStf::get_events(&mut state).len(), 0);
}
