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
			EnclaveExtrinsicsFactory, EnclaveImmediateParentchainBlockImportDispatcher,
			EnclaveIndirectCallsExecutor, EnclaveNodeMetadataRepository,
			EnclaveOffchainWorkerExecutor, EnclaveParentchainBlockImportDispatcher,
			EnclaveParentchainBlockImportQueue, EnclaveParentchainBlockImporter,
			EnclaveParentchainEventImportQueue, EnclaveParentchainSigner, EnclaveStfExecutor,
			EnclaveTriggeredParentchainBlockImportDispatcher, EnclaveValidatorAccessor,
			GLOBAL_OCALL_API_COMPONENT, GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT,
			GLOBAL_SIGNING_KEY_REPOSITORY_COMPONENT, GLOBAL_STATE_HANDLER_COMPONENT,
			GLOBAL_STATE_OBSERVER_COMPONENT, GLOBAL_TOP_POOL_AUTHOR_COMPONENT,
		},
		EnclaveStfEnclaveSigner,
	},
};
use itp_component_container::ComponentGetter;
use itp_nonce_cache::GLOBAL_NONCE_CACHE;
use itp_sgx_crypto::key_repository::AccessKey;
use log::*;
use sp_core::H256;
use std::sync::Arc;

pub(crate) fn create_parentchain_block_importer(
	validator_access: Arc<EnclaveValidatorAccessor>,
	stf_executor: Arc<EnclaveStfExecutor>,
	extrinsics_factory: Arc<EnclaveExtrinsicsFactory>,
	node_metadata_repository: Arc<EnclaveNodeMetadataRepository>,
) -> Result<EnclaveParentchainBlockImporter> {
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
	let indirect_calls_executor = Arc::new(EnclaveIndirectCallsExecutor::new(
		shielding_key_repository,
		stf_enclave_signer,
		top_pool_author,
		node_metadata_repository,
	));
	Ok(EnclaveParentchainBlockImporter::new(
		validator_access,
		stf_executor,
		extrinsics_factory,
		indirect_calls_executor,
	))
}

pub(crate) fn create_extrinsics_factory(
	genesis_hash: H256,
	node_metadata_repository: Arc<EnclaveNodeMetadataRepository>,
) -> Result<Arc<EnclaveExtrinsicsFactory>> {
	let signer = GLOBAL_SIGNING_KEY_REPOSITORY_COMPONENT.get()?.retrieve_key()?;

	Ok(Arc::new(EnclaveExtrinsicsFactory::new(
		genesis_hash,
		EnclaveParentchainSigner::new(signer),
		GLOBAL_NONCE_CACHE.clone(),
		node_metadata_repository,
	)))
}

pub(crate) fn create_offchain_immediate_import_dispatcher(
	stf_executor: Arc<EnclaveStfExecutor>,
	block_importer: EnclaveParentchainBlockImporter,
	validator_access: Arc<EnclaveValidatorAccessor>,
	extrinsics_factory: Arc<EnclaveExtrinsicsFactory>,
) -> Result<Arc<EnclaveParentchainBlockImportDispatcher>> {
	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
	let top_pool_author = GLOBAL_TOP_POOL_AUTHOR_COMPONENT.get()?;

	let offchain_worker_executor = Arc::new(EnclaveOffchainWorkerExecutor::new(
		top_pool_author,
		stf_executor,
		state_handler,
		validator_access,
		extrinsics_factory,
	));
	let immediate_dispatcher = EnclaveImmediateParentchainBlockImportDispatcher::new(
		block_importer,
	)
	.with_observer(move || {
		if let Err(e) = offchain_worker_executor.execute() {
			error!("Failed to execute trusted calls: {:?}", e);
		}
	});

	Ok(Arc::new(EnclaveParentchainBlockImportDispatcher::new_immediate_dispatcher(Arc::new(
		immediate_dispatcher,
	))))
}

pub(crate) fn create_sidechain_triggered_import_dispatcher(
	block_importer: EnclaveParentchainBlockImporter,
) -> Arc<EnclaveParentchainBlockImportDispatcher> {
	let parentchain_block_import_queue = EnclaveParentchainBlockImportQueue::default();
	let parentchain_event_import_queue = EnclaveParentchainEventImportQueue::default();
	let triggered_dispatcher = EnclaveTriggeredParentchainBlockImportDispatcher::new(
		block_importer,
		parentchain_block_import_queue,
		parentchain_event_import_queue,
	);
	Arc::new(EnclaveParentchainBlockImportDispatcher::new_triggered_dispatcher(Arc::new(
		triggered_dispatcher,
	)))
}
