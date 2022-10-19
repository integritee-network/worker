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
			GLOBAL_FULL_SOLOCHAIN_HANDLER_COMPONENT, GLOBAL_OCALL_API_COMPONENT,
			GLOBAL_STATE_HANDLER_COMPONENT,
		},
		parentchain::common::{
			create_extrinsics_factory, create_offchain_immediate_import_dispatcher,
			create_parentchain_block_importer, create_sidechain_triggered_import_dispatcher,
		},
	},
};
use codec::Encode;
use itc_parentchain::{
	block_import_dispatcher::DispatchBlockImport,
	light_client::{
		concurrent_access::ValidatorAccess, light_client_init_params::LightClientInitParams,
		LightClientState,
	},
};
use itp_component_container::{ComponentGetter, ComponentInitializer};
use itp_settings::worker_mode::ProvideWorkerMode;
use itp_types::{Block as ParentchainBlock, Header as ParentchainHeader};
use sp_runtime::traits::{Block as BlockTrait, Header as HeaderTrait};
use std::{sync::Arc, vec::Vec};

pub struct FullSolochainHandler<Block: BlockTrait> {
	pub genesis_header: Block::Header,
	pub node_metadata_repository: Arc<EnclaveNodeMetadataRepository>,
	pub stf_executor: Arc<EnclaveStfExecutor>,
	pub validator_accessor: Arc<EnclaveValidatorAccessor>,
	pub extrinsics_factory: Arc<EnclaveExtrinsicsFactory>,
	pub import_dispatcher: Option<Arc<EnclaveParentchainBlockImportDispatcher>>,
}

impl<Block: BlockTrait> FullSolochainHandler<Block> {
	pub fn init<WorkerModeProvider: ProvideWorkerMode>(
		params: LightClientInitParams<Block::Header>,
	) -> Result<Vec<u8>> {
		let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;
		let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
		let node_metadata_repository = Arc::new(EnclaveNodeMetadataRepository::default());

		let validator = itc_parentchain::light_client::io::read_or_init_validator::<
			ParentchainBlock,
			EnclaveOCallApi,
		>(params, ocall_api.clone())?;
		let latest_header = validator.latest_finalized_header(validator.num_relays())?;
		let validator_accessor = Arc::new(EnclaveValidatorAccessor::new(validator));
		let genesis_header = params.get_genesis_header();

		let genesis_hash =
			validator_accessor.execute_on_validator(|v| v.genesis_hash(v.num_relays()))?;

		let extrinsics_factory =
			create_extrinsics_factory(genesis_hash, node_metadata_repository.clone())?;

		// FIXME: Probably should be split up into a parentchain dependent executor and one independent.
		let stf_executor =
			Arc::new(EnclaveStfExecutor::new(ocall_api, state_handler, node_metadata_repository));

		let block_importer = create_parentchain_block_importer(
			validator_accessor,
			stf_executor,
			extrinsics_factory,
			node_metadata_repository,
		)?;

		let import_dispatcher = match WorkerModeProvider::worker_mode() {
			WorkerMode::OffChainWorker => Some(create_offchain_immediate_import_dispatcher(
				stf_executor,
				block_importer,
				validator_accessor,
				extrinsics_factory,
			)),
			WorkerMode::Sidechain =>
				Some(create_sidechain_triggered_import_dispatcher(block_importer)),
			WorkerMode::Teeracle => None,
		};

		let solochain_handler = Arc::new(Self {
			genesis_header: *genesis_header,
			node_metadata_repository,
			stf_executor,
			validator_accessor,
			extrinsics_factory,
			import_dispatcher,
		});

		GLOBAL_FULL_SOLOCHAIN_HANDLER_COMPONENT.initialize(solochain_handler);

		Ok(latest_header.encode())
	}
}
