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
			EnclaveExtrinsicsFactory, EnclaveNodeMetadataRepository, EnclaveOCallApi,
			EnclaveParentchainBlockImportDispatcher, EnclaveStfExecutor, EnclaveValidatorAccessor,
			GLOBAL_FULL_PARACHAIN_HANDLER_COMPONENT, GLOBAL_OCALL_API_COMPONENT,
			GLOBAL_STATE_HANDLER_COMPONENT,
		},
		parentchain::common::{
			create_extrinsics_factory, create_offchain_immediate_import_dispatcher,
			create_parentchain_block_importer, create_sidechain_triggered_import_dispatcher,
			HeaderFor,
		},
	},
};
use codec::{Decode, Encode};
use itc_parentchain::light_client::{
	concurrent_access::ValidatorAccess, light_client_init_params::ParachainParams, LightClientState,
};
use itp_component_container::{ComponentGetter, ComponentInitializer};
use itp_settings::worker_mode::{ProvideWorkerMode, WorkerMode};
use itp_types::Block as ParentchainBlock;
use std::{sync::Arc, vec::Vec};

#[derive(Clone)]
pub struct FullParachainHandler {
	pub genesis_header: HeaderFor<ParentchainBlock>,
	pub node_metadata_repository: Arc<EnclaveNodeMetadataRepository>,
	// FIXME: Probably should be split up into a parentchain dependent executor and one independent.
	pub stf_executor: Arc<EnclaveStfExecutor>,
	pub validator_accessor: Arc<EnclaveValidatorAccessor>,
	pub extrinsics_factory: Arc<EnclaveExtrinsicsFactory>,
	pub import_dispatcher: Arc<EnclaveParentchainBlockImportDispatcher>,
}

impl FullParachainHandler {
	pub fn init<WorkerModeProvider: ProvideWorkerMode>(encoded_params: Vec<u8>) -> Result<Vec<u8>> {
		let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;
		let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
		let node_metadata_repository = Arc::new(EnclaveNodeMetadataRepository::default());

		let params =
			ParachainParams::<HeaderFor<ParentchainBlock>>::decode(&mut encoded_params.as_slice())?;
		let genesis_header = params.genesis_header.clone();

		let validator = itc_parentchain::light_client::io::read_or_init_parachain_validator::<
			ParentchainBlock,
			EnclaveOCallApi,
		>(params, ocall_api.clone())?;
		let latest_header = validator.latest_finalized_header(validator.num_relays())?;
		let validator_accessor = Arc::new(EnclaveValidatorAccessor::new(validator));

		let genesis_hash =
			validator_accessor.execute_on_validator(|v| v.genesis_hash(v.num_relays()))?;

		let extrinsics_factory =
			create_extrinsics_factory(genesis_hash, node_metadata_repository.clone())?;

		let stf_executor = Arc::new(EnclaveStfExecutor::new(
			ocall_api,
			state_handler,
			node_metadata_repository.clone(),
		));

		let block_importer = create_parentchain_block_importer(
			validator_accessor.clone(),
			stf_executor.clone(),
			extrinsics_factory.clone(),
			node_metadata_repository.clone(),
		)?;

		let import_dispatcher = match WorkerModeProvider::worker_mode() {
			WorkerMode::OffChainWorker => create_offchain_immediate_import_dispatcher(
				stf_executor.clone(),
				block_importer,
				validator_accessor.clone(),
				extrinsics_factory.clone(),
			)?,
			WorkerMode::Sidechain => create_sidechain_triggered_import_dispatcher(block_importer),
			WorkerMode::Teeracle =>
				Arc::new(EnclaveParentchainBlockImportDispatcher::new_empty_dispatcher()),
		};

		let parachain_handler = Arc::new(Self {
			genesis_header,
			node_metadata_repository,
			stf_executor,
			validator_accessor,
			extrinsics_factory,
			import_dispatcher,
		});

		GLOBAL_FULL_PARACHAIN_HANDLER_COMPONENT.initialize(parachain_handler);

		Ok(latest_header.encode())
	}
}
