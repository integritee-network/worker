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
	error::Result,
	initialization::{
		global_components::{
			EnclaveExtrinsicsFactory, EnclaveNodeMetadataRepository, EnclaveOffchainWorkerExecutor,
			EnclaveParentchainSigner, EnclaveStfExecutor, EnclaveValidatorAccessor,
			IntegriteeEnclaveExtrinsicsFactory, IntegriteeParentchainBlockImportDispatcher,
			IntegriteeParentchainBlockImportQueue, IntegriteeParentchainBlockImporter,
			IntegriteeParentchainEventImportQueue,
			IntegriteeParentchainImmediateBlockImportDispatcher,
			IntegriteeParentchainIndirectCallsExecutor,
			IntegriteeParentchainTriggeredBlockImportDispatcher, TargetAEnclaveExtrinsicsFactory,
			TargetAParentchainBlockImportDispatcher, TargetAParentchainBlockImportQueue,
			TargetAParentchainBlockImporter, TargetAParentchainEventImportQueue,
			TargetAParentchainImmediateBlockImportDispatcher,
			TargetAParentchainIndirectCallsExecutor,
			TargetAParentchainTriggeredBlockImportDispatcher, TargetBEnclaveExtrinsicsFactory,
			TargetBParentchainBlockImportDispatcher, TargetBParentchainBlockImportQueue,
			TargetBParentchainBlockImporter, TargetBParentchainEventImportQueue,
			TargetBParentchainImmediateBlockImportDispatcher,
			TargetBParentchainIndirectCallsExecutor,
			TargetBParentchainTriggeredBlockImportDispatcher, GLOBAL_OCALL_API_COMPONENT,
			GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT, GLOBAL_SIGNING_KEY_REPOSITORY_COMPONENT,
			GLOBAL_STATE_HANDLER_COMPONENT, GLOBAL_STATE_OBSERVER_COMPONENT,
			GLOBAL_TOP_POOL_AUTHOR_COMPONENT,
		},
		EnclaveStfEnclaveSigner,
	},
};
use ita_parentchain_interface::Config;
use itp_component_container::ComponentGetter;
use itp_nonce_cache::NonceCache;
use itp_sgx_crypto::key_repository::AccessKey;
use itp_stf_interface::ShardCreationInfo;
use itp_types::parentchain::ParentchainId;
use log::*;
use sp_core::H256;
use std::sync::Arc;

pub(crate) fn create_integritee_parentchain_block_importer(
	validator_access: Arc<EnclaveValidatorAccessor>,
	stf_executor: Arc<EnclaveStfExecutor>,
	extrinsics_factory: Arc<IntegriteeEnclaveExtrinsicsFactory>,
	node_metadata_repository: Arc<EnclaveNodeMetadataRepository>,
	shard_creation_info: ShardCreationInfo,
) -> Result<IntegriteeParentchainBlockImporter> {
	let state_observer = GLOBAL_STATE_OBSERVER_COMPONENT.get()?;
	let top_pool_author = GLOBAL_TOP_POOL_AUTHOR_COMPONENT.get()?;
	let shielding_key_repository = GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT.get()?;
	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;

	let stf_enclave_signer = Arc::new(EnclaveStfEnclaveSigner::new(
		state_observer,
		ocall_api,
		shielding_key_repository.clone(),
		top_pool_author.clone(),
	));
	let indirect_calls_executor = Arc::new(IntegriteeParentchainIndirectCallsExecutor::new(
		shielding_key_repository,
		stf_enclave_signer,
		top_pool_author,
		node_metadata_repository,
		ParentchainId::Integritee,
	));
	Ok(IntegriteeParentchainBlockImporter::new(
		validator_access,
		stf_executor,
		extrinsics_factory,
		indirect_calls_executor,
		shard_creation_info,
		ParentchainId::Integritee,
	))
}

pub(crate) fn create_target_a_parentchain_block_importer(
	validator_access: Arc<EnclaveValidatorAccessor>,
	stf_executor: Arc<EnclaveStfExecutor>,
	extrinsics_factory: Arc<TargetAEnclaveExtrinsicsFactory>,
	node_metadata_repository: Arc<EnclaveNodeMetadataRepository>,
	shard_creation_info: ShardCreationInfo,
) -> Result<TargetAParentchainBlockImporter> {
	let state_observer = GLOBAL_STATE_OBSERVER_COMPONENT.get()?;
	let top_pool_author = GLOBAL_TOP_POOL_AUTHOR_COMPONENT.get()?;
	let shielding_key_repository = GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT.get()?;
	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;

	let stf_enclave_signer = Arc::new(EnclaveStfEnclaveSigner::new(
		state_observer,
		ocall_api,
		shielding_key_repository.clone(),
		top_pool_author.clone(),
	));
	let indirect_calls_executor = Arc::new(TargetAParentchainIndirectCallsExecutor::new(
		shielding_key_repository,
		stf_enclave_signer,
		top_pool_author,
		node_metadata_repository,
		ParentchainId::TargetA,
	));
	Ok(TargetAParentchainBlockImporter::new(
		validator_access,
		stf_executor,
		extrinsics_factory,
		indirect_calls_executor,
		shard_creation_info,
		ParentchainId::TargetA,
	))
}

pub(crate) fn create_target_b_parentchain_block_importer(
	validator_access: Arc<EnclaveValidatorAccessor>,
	stf_executor: Arc<EnclaveStfExecutor>,
	extrinsics_factory: Arc<TargetBEnclaveExtrinsicsFactory>,
	node_metadata_repository: Arc<EnclaveNodeMetadataRepository>,
	shard_creation_info: ShardCreationInfo,
) -> Result<TargetBParentchainBlockImporter> {
	let state_observer = GLOBAL_STATE_OBSERVER_COMPONENT.get()?;
	let top_pool_author = GLOBAL_TOP_POOL_AUTHOR_COMPONENT.get()?;
	let shielding_key_repository = GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT.get()?;
	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;

	let stf_enclave_signer = Arc::new(EnclaveStfEnclaveSigner::new(
		state_observer,
		ocall_api,
		shielding_key_repository.clone(),
		top_pool_author.clone(),
	));
	let indirect_calls_executor = Arc::new(TargetBParentchainIndirectCallsExecutor::new(
		shielding_key_repository,
		stf_enclave_signer,
		top_pool_author,
		node_metadata_repository,
		ParentchainId::TargetB,
	));
	Ok(TargetBParentchainBlockImporter::new(
		validator_access,
		stf_executor,
		extrinsics_factory,
		indirect_calls_executor,
		shard_creation_info,
		ParentchainId::TargetB,
	))
}

pub(crate) fn create_extrinsics_factory<NodeRuntimeConfig: Config, Tip>(
	genesis_hash: H256,
	nonce_cache: Arc<NonceCache>,
	node_metadata_repository: Arc<EnclaveNodeMetadataRepository>,
) -> Result<Arc<EnclaveExtrinsicsFactory<NodeRuntimeConfig, Tip>>> {
	let signer = GLOBAL_SIGNING_KEY_REPOSITORY_COMPONENT.get()?.retrieve_key()?;

	Ok(Arc::new(EnclaveExtrinsicsFactory::new(
		genesis_hash,
		EnclaveParentchainSigner::new(signer),
		nonce_cache,
		node_metadata_repository,
	)))
}

pub(crate) fn create_integritee_offchain_immediate_import_dispatcher(
	stf_executor: Arc<EnclaveStfExecutor>,
	block_importer: IntegriteeParentchainBlockImporter,
	validator_access: Arc<EnclaveValidatorAccessor>,
	extrinsics_factory: Arc<IntegriteeEnclaveExtrinsicsFactory>,
) -> Result<Arc<IntegriteeParentchainBlockImportDispatcher>> {
	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
	let top_pool_author = GLOBAL_TOP_POOL_AUTHOR_COMPONENT.get()?;

	let offchain_worker_executor = Arc::new(EnclaveOffchainWorkerExecutor::new(
		top_pool_author,
		stf_executor,
		state_handler,
		validator_access,
		extrinsics_factory,
	));
	let immediate_dispatcher = IntegriteeParentchainImmediateBlockImportDispatcher::new(
		block_importer,
	)
	.with_observer(move || {
		if let Err(e) = offchain_worker_executor.execute() {
			error!("Failed to execute trusted calls: {:?}", e);
		}
	});

	Ok(Arc::new(IntegriteeParentchainBlockImportDispatcher::new_immediate_dispatcher(Arc::new(
		immediate_dispatcher,
	))))
}

pub(crate) fn create_target_a_offchain_immediate_import_dispatcher(
	stf_executor: Arc<EnclaveStfExecutor>,
	block_importer: TargetAParentchainBlockImporter,
	validator_access: Arc<EnclaveValidatorAccessor>,
	extrinsics_factory: Arc<TargetAEnclaveExtrinsicsFactory>,
) -> Result<Arc<TargetAParentchainBlockImportDispatcher>> {
	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
	let top_pool_author = GLOBAL_TOP_POOL_AUTHOR_COMPONENT.get()?;

	let offchain_worker_executor = Arc::new(EnclaveOffchainWorkerExecutor::new(
		top_pool_author,
		stf_executor,
		state_handler,
		validator_access,
		extrinsics_factory,
	));
	let immediate_dispatcher = TargetAParentchainImmediateBlockImportDispatcher::new(
		block_importer,
	)
	.with_observer(move || {
		if let Err(e) = offchain_worker_executor.execute() {
			error!("Failed to execute trusted calls: {:?}", e);
		}
	});

	Ok(Arc::new(TargetAParentchainBlockImportDispatcher::new_immediate_dispatcher(Arc::new(
		immediate_dispatcher,
	))))
}

pub(crate) fn create_target_b_offchain_immediate_import_dispatcher(
	stf_executor: Arc<EnclaveStfExecutor>,
	block_importer: TargetBParentchainBlockImporter,
	validator_access: Arc<EnclaveValidatorAccessor>,
	extrinsics_factory: Arc<TargetBEnclaveExtrinsicsFactory>,
) -> Result<Arc<TargetBParentchainBlockImportDispatcher>> {
	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
	let top_pool_author = GLOBAL_TOP_POOL_AUTHOR_COMPONENT.get()?;

	let offchain_worker_executor = Arc::new(EnclaveOffchainWorkerExecutor::new(
		top_pool_author,
		stf_executor,
		state_handler,
		validator_access,
		extrinsics_factory,
	));
	let immediate_dispatcher = TargetBParentchainImmediateBlockImportDispatcher::new(
		block_importer,
	)
	.with_observer(move || {
		if let Err(e) = offchain_worker_executor.execute() {
			error!("Failed to execute trusted calls: {:?}", e);
		}
	});

	Ok(Arc::new(TargetBParentchainBlockImportDispatcher::new_immediate_dispatcher(Arc::new(
		immediate_dispatcher,
	))))
}

pub(crate) fn create_sidechain_triggered_import_dispatcher(
	block_importer: IntegriteeParentchainBlockImporter,
) -> Arc<IntegriteeParentchainBlockImportDispatcher> {
	let parentchain_block_import_queue = IntegriteeParentchainBlockImportQueue::default();
	let parentchain_event_import_queue = IntegriteeParentchainEventImportQueue::default();
	let triggered_dispatcher = IntegriteeParentchainTriggeredBlockImportDispatcher::new(
		block_importer,
		parentchain_block_import_queue,
		parentchain_event_import_queue,
	);
	Arc::new(IntegriteeParentchainBlockImportDispatcher::new_triggered_dispatcher(Arc::new(
		triggered_dispatcher,
	)))
}

pub(crate) fn create_sidechain_triggered_import_dispatcher_for_target_a(
	block_importer: TargetAParentchainBlockImporter,
) -> Arc<TargetAParentchainBlockImportDispatcher> {
	let parentchain_block_import_queue = TargetAParentchainBlockImportQueue::default();
	let parentchain_event_import_queue = TargetAParentchainEventImportQueue::default();
	let triggered_dispatcher = TargetAParentchainTriggeredBlockImportDispatcher::new(
		block_importer,
		parentchain_block_import_queue,
		parentchain_event_import_queue,
	);
	Arc::new(TargetAParentchainBlockImportDispatcher::new_triggered_dispatcher(Arc::new(
		triggered_dispatcher,
	)))
}

pub(crate) fn create_sidechain_triggered_import_dispatcher_for_target_b(
	block_importer: TargetBParentchainBlockImporter,
) -> Arc<TargetBParentchainBlockImportDispatcher> {
	let parentchain_block_import_queue = TargetBParentchainBlockImportQueue::default();
	let parentchain_event_import_queue = TargetBParentchainEventImportQueue::default();
	let triggered_dispatcher = TargetBParentchainTriggeredBlockImportDispatcher::new(
		block_importer,
		parentchain_block_import_queue,
		parentchain_event_import_queue,
	);
	Arc::new(TargetBParentchainBlockImportDispatcher::new_triggered_dispatcher(Arc::new(
		triggered_dispatcher,
	)))
}
