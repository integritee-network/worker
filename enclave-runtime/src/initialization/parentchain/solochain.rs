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

use super::common::{
	create_extrinsic_factory, create_offchain_immediate_import_dispatcher,
	create_parentchain_import_queue, create_sidechain_triggered_import_dispatcher,
};
use itc_parentchain::block_import_dispatcher::DispatchBlockImport;
use itp_node_api::metadata::provider::AccessNodeMetadata;
use sp_runtime::traits::Header as HeaderTrait;
use std::sync::Arc;

pub struct FullSolochainHandler<
	Header,
	NodeMetadataRepository,
	LightClient,
	ExtrinsicsFactory,
	ImportDispatcher,
> {
	pub genesis_header: Header,
	pub node_metadata_repository: NodeMetadataRepository,
	pub validator_accessor: Arc<LightClient>,
	pub extrinsics_factory: Arc<ExtrinsicsFactory>,
	pub import_dispatcher: Option<Arc<ImportDispatcher>>,
}

impl<Header, NodeMetadataRepository, LightClient, ExtrinsicsFactory, ImportDispatcher>
	SolochainHandler
where
	Header: HeaderTrait,
	LightClient: ValidatorAccess,
	ExtrinsicsFactory: CreateExtrinsics,
	NodeMetadataRepository: AccessNodeMetadata,
	ImmediateImportDispatcher: DispatchBlockImport,
{
	pub fn init<WorkerModeProvider: ProvideWorkerMode>(
		params: LightClientInitParams<Header>,
	) -> Result<Header> {
		let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;
		let validator = itc_parentchain::light_client::io::read_or_init_validator::<Block, OcallApi>(
			params, ocall_api,
		)?;
		let latest_header = validator.latest_finalized_header(validator.num_relays())?;
		let validator_access = Arc::new(EnclaveValidatorAccessor::new(validator));
		let genesis_header = params.get_genesis_header();

		let genesis_hash =
			validator_access.execute_on_validator(|v| v.genesis_hash(v.num_relays()))?;

		let extrinsics_factory = create_extrinsic_factory(genesis_hash)?;

		let block_importer = create_parentchain_block_importer()?;

		let import_dispatcher = match WorkerModeProvider::worker_mode() {
			WorkerMode::OffChainWorker => Some(create_offchain_immediate_import_dispatcher),
			WorkerMode::Sidechain => Some(create_sidechain_triggered_import_dispatcher),
			WorkerMode::Teeracle => None,
		};

		let node_metadata_repository = GLOBAL_NODE_METADATA_REPOSITORY_COMPONENT.get()?;

		let solochain_handler = Self {
			genesis_header,
			node_metadata_repository,
			validator_accessor,
			extrinsics_factory,
			import_dispatcher,
		};

		GLOBAL_FULL_SOLOCHAIN_HANDLER_COMPONENT.initialize(solochain_handler);

		Ok(latest_header)
	}
}
