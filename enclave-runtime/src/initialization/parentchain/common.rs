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

use itc_parentchain::block_import_dispatcher::BlockImportDispatcher;

use crate::initialization::global_components::{EnclaveExtrinsicsFactory, EnclaveNodeMetadataRepository};

pub(crate) fn create_parentchain_block_importer(validator_access: Arc<EnclaveValidatorAccessor>, extrinsics_factory: Arc<EnclaveExtrinsicsFactory>, node_metadata_repository: Arc<EnclaveNodeMetadataRepository>)
-> EnclaveResult<Arc<ParentchainBlockImporter>> {
	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
	let state_observer = GLOBAL_STATE_OBSERVER_COMPONENT.get()?;
	let stf_executor = GLOBAL_STF_EXECUTOR_COMPONENT.get()?;
	let top_pool_author = GLOBAL_TOP_POOL_AUTHOR_COMPONENT.get()?;
	let shielding_key_repository = GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT.get()?;
	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;

	let stf_enclave_signer = Arc::new(EnclaveStfEnclaveSigner::new(
		state_observer,
		ocall_api,
		shielding_key_repository.clone(),
	));
	let indirect_calls_executor = Arc::new(IndirectCallsExecutor::new(
		shielding_key_repository,
		stf_enclave_signer,
		top_pool_author.clone(),
		node_metadata_repository,
	));
	Ok(Arc::new(ParentchainBlockImporter::new(
		validator_access.clone(),
		stf_executor.clone(),
		extrinsics_factory.clone(),
		indirect_calls_executor,
	)))
}


pub (crate) fn create_extrinsic_factory(genesis_hash: H256) -> Result<Arc<ExtrinsicsFactory>> {
	let signer = Ed25519Seal::unseal_from_static_file()?;
	GLOBAL_NONCE_CACHE.clone(),
	let node_metadata_repository = GLOBAL_NODE_METADATA_REPOSITORY_COMPONENT.get()?;

	Ok(Arc::new(ExtrinsicsFactory::new(
		genesis_hash,
		signer,
		GLOBAL_NONCE_CACHE.clone(),
		node_metadata_repository,
	)))

}

fn create_offchain_immediate_import_dispatcher(block_importer: Arc<ParentchainBlockImporter>) -> Arc<BlockImportDispatcher> {
	let offchain_worker_executor = Arc::new(EnclaveOffchainWorkerExecutor::new(
		top_pool_author,
		stf_executor,
		state_handler,
		validator_access,
		extrinsics_factory,
	));
	let immediate_dispatcher =
		ImmediateDispatcher::new(parentchain_block_importer).with_observer(move || {
			if let Err(e) = offchain_worker_executor.execute() {
				error!("Failed to execute trusted calls: {:?}", e);
			}
		});

	Arc::new(BlockImportDispatcher::new_immediate_dispatcher(immediate_dispatcher))
}

fn create_sidechain_triggered_import_dispatcher(block_importer: Arc<ParentchainBlockImporter>) -> Arc<BlockImportDispatcher> {
	let parentchain_block_import_queue = BlockImportQueue::<SignedBlock>::default();
	let triggered_dispatcher = TriggeredDispatcher::new(
		parentchain_block_importer,
		parentchain_block_import_queue,
	);
	Arc::new(BlockImportDispatcher::new_triggered_dispatcher(triggered_dispatcher))

}
