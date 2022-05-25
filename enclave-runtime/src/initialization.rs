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
	error::{Error, Result as EnclaveResult},
	global_components::{
		EnclaveOCallApi, EnclaveRpcConnectionRegistry, EnclaveRpcResponder,
		EnclaveShieldingKeyRepository, EnclaveSidechainApi, EnclaveSidechainBlockImportQueue,
		EnclaveSidechainBlockImportQueueWorker, EnclaveSidechainBlockImporter,
		EnclaveSidechainBlockSyncer, EnclaveStateFileIo, EnclaveStateHandler,
		EnclaveStateKeyRepository, EnclaveStfEnclaveSigner, EnclaveStfExecutor, EnclaveTopPool,
		EnclaveTopPoolAuthor, EnclaveTopPoolOperationHandler, EnclaveValidatorAccessor,
		GLOBAL_EXTRINSICS_FACTORY_COMPONENT, GLOBAL_OCALL_API_COMPONENT,
		GLOBAL_PARENTCHAIN_IMPORT_DISPATCHER_COMPONENT, GLOBAL_RPC_WS_HANDLER_COMPONENT,
		GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT, GLOBAL_SIDECHAIN_BLOCK_COMPOSER_COMPONENT,
		GLOBAL_SIDECHAIN_BLOCK_SYNCER_COMPONENT, GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT,
		GLOBAL_SIDECHAIN_IMPORT_QUEUE_WORKER_COMPONENT, GLOBAL_STATE_HANDLER_COMPONENT,
		GLOBAL_STATE_KEY_REPOSITORY_COMPONENT, GLOBAL_STF_EXECUTOR_COMPONENT,
		GLOBAL_TOP_POOL_AUTHOR_COMPONENT, GLOBAL_TOP_POOL_OPERATION_HANDLER_COMPONENT,
		GLOBAL_WEB_SOCKET_SERVER_COMPONENT,
	},
	ocall::OcallApi,
	rpc::{rpc_response_channel::RpcResponseChannel, worker_api_direct::public_api_rpc_handler},
	Hash,
};
use base58::ToBase58;
use codec::Encode;
use ita_stf::State as StfState;
use itc_direct_rpc_server::{
	create_determine_watch, rpc_connection_registry::ConnectionRegistry,
	rpc_ws_handler::RpcWsHandler,
};
use itc_parentchain::{
	block_import_dispatcher::triggered_dispatcher::TriggeredDispatcher,
	block_importer::ParentchainBlockImporter, indirect_calls_executor::IndirectCallsExecutor,
	light_client::Validator,
};
use itc_tls_websocket_server::{create_ws_server, ConnectionToken, WebSocketServer};
use itp_block_import_queue::BlockImportQueue;
use itp_component_container::{ComponentGetter, ComponentInitializer};
use itp_extrinsics_factory::ExtrinsicsFactory;
use itp_nonce_cache::GLOBAL_NONCE_CACHE;
use itp_primitives_cache::GLOBAL_PRIMITIVES_CACHE;
use itp_settings::files::STATE_SNAPSHOTS_CACHE_SIZE;
use itp_sgx_crypto::{
	aes, ed25519, ed25519_derivation::DeriveEd25519, rsa3072, AesSeal, Ed25519Seal, Rsa3072Seal,
};
use itp_sgx_io::StaticSealedIO;
use itp_stf_state_handler::{
	handle_state::HandleState, query_shard_state::QueryShardState,
	state_snapshot_repository_loader::StateSnapshotRepositoryLoader, StateHandler,
};
use itp_top_pool::pool::Options as PoolOptions;
use itp_top_pool_author::author::AuthorTopFilter;
use itp_types::{
	light_client_init_params::LightClientInitParams, Block, Header, ShardIdentifier, SignedBlock,
};
use its_sidechain::{
	aura::block_importer::BlockImporter, block_composer::BlockComposer,
	top_pool_executor::TopPoolOperationHandler,
};
use log::*;
use primitive_types::H256;
use sp_core::crypto::Pair;
use std::{boxed::Box, string::String, sync::Arc};

pub(crate) fn init_enclave(mu_ra_url: String, untrusted_worker_url: String) -> EnclaveResult<()> {
	// Initialize the logging environment in the enclave.
	env_logger::init();

	ed25519::create_sealed_if_absent().map_err(Error::Crypto)?;
	let signer = Ed25519Seal::unseal_from_static_file().map_err(Error::Crypto)?;
	info!("[Enclave initialized] Ed25519 prim raw : {:?}", signer.public().0);

	rsa3072::create_sealed_if_absent()?;

	let shielding_key = Rsa3072Seal::unseal_from_static_file()?;

	let shielding_key_repository =
		Arc::new(EnclaveShieldingKeyRepository::new(shielding_key, Arc::new(Rsa3072Seal)));
	GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT.initialize(shielding_key_repository.clone());

	// Create the aes key that is used for state encryption such that a key is always present in tests.
	// It will be overwritten anyway if mutual remote attestation is performed with the primary worker.
	aes::create_sealed_if_absent().map_err(Error::Crypto)?;

	let state_key = AesSeal::unseal_from_static_file()?;
	let state_key_repository =
		Arc::new(EnclaveStateKeyRepository::new(state_key, Arc::new(AesSeal)));
	GLOBAL_STATE_KEY_REPOSITORY_COMPONENT.initialize(state_key_repository.clone());

	let enclave_call_signer_key = shielding_key.derive_ed25519()?;
	let state_file_io = Arc::new(EnclaveStateFileIo::new(
		state_key_repository,
		enclave_call_signer_key.public().into(),
	));
	let state_snapshot_repository_loader =
		StateSnapshotRepositoryLoader::<EnclaveStateFileIo, StfState, H256>::new(state_file_io);
	let state_snapshot_repository =
		state_snapshot_repository_loader.load_snapshot_repository(STATE_SNAPSHOTS_CACHE_SIZE)?;

	let state_handler = Arc::new(StateHandler::new(state_snapshot_repository));
	GLOBAL_STATE_HANDLER_COMPONENT.initialize(state_handler.clone());

	let ocall_api = Arc::new(OcallApi);
	GLOBAL_OCALL_API_COMPONENT.initialize(ocall_api.clone());

	let stf_executor = Arc::new(EnclaveStfExecutor::new(ocall_api.clone(), state_handler.clone()));
	GLOBAL_STF_EXECUTOR_COMPONENT.initialize(stf_executor);

	// For debug purposes, list shards. no problem to panic if fails.
	let shards = state_handler.list_shards().unwrap();
	debug!("found the following {} shards on disk:", shards.len());
	for s in shards {
		debug!("{}", s.encode().to_base58())
	}

	itp_primitives_cache::set_primitives(
		GLOBAL_PRIMITIVES_CACHE.as_ref(),
		mu_ra_url,
		untrusted_worker_url,
	)
	.map_err(Error::PrimitivesAccess)?;

	let watch_extractor = Arc::new(create_determine_watch::<Hash>());

	let connection_registry = Arc::new(ConnectionRegistry::<Hash, ConnectionToken>::new());

	// We initialize components for the public RPC / direct invocation server here, so we can start the server
	// before registering on the parentchain. If we started the RPC AFTER registering on the parentchain and
	// initializing the light-client, there is a period of time where a peer might want to reach us,
	// but the RPC server is not yet up and running, resulting in error messages or even in that
	// validateer completely breaking (IO PipeError).
	// Corresponding GH issues are #545 and #600.

	let top_pool_author = create_top_pool_author(
		connection_registry.clone(),
		state_handler,
		ocall_api,
		shielding_key_repository,
	);
	GLOBAL_TOP_POOL_AUTHOR_COMPONENT.initialize(top_pool_author.clone());

	let io_handler = public_api_rpc_handler(top_pool_author);
	let rpc_handler = Arc::new(RpcWsHandler::new(io_handler, watch_extractor, connection_registry));
	GLOBAL_RPC_WS_HANDLER_COMPONENT.initialize(rpc_handler);

	let sidechain_block_import_queue = Arc::new(EnclaveSidechainBlockImportQueue::default());
	GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT.initialize(sidechain_block_import_queue);

	Ok(())
}

pub(crate) fn init_enclave_sidechain_components() -> EnclaveResult<()> {
	let stf_executor = GLOBAL_STF_EXECUTOR_COMPONENT.get()?;
	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;

	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;
	let top_pool_author = GLOBAL_TOP_POOL_AUTHOR_COMPONENT.get()?;

	let top_pool_operation_handler = Arc::new(EnclaveTopPoolOperationHandler::new(
		top_pool_author.clone(),
		stf_executor.clone(),
	));
	GLOBAL_TOP_POOL_OPERATION_HANDLER_COMPONENT.initialize(top_pool_operation_handler);

	let top_pool_executor = Arc::<EnclaveTopPoolOperationHandler>::new(
		TopPoolOperationHandler::new(top_pool_author, stf_executor),
	);

	let parentchain_block_import_dispatcher =
		GLOBAL_PARENTCHAIN_IMPORT_DISPATCHER_COMPONENT.get()?;

	let state_key_repository = GLOBAL_STATE_KEY_REPOSITORY_COMPONENT.get()?;

	let signer = Ed25519Seal::unseal_from_static_file()?;

	let sidechain_block_importer = Arc::<EnclaveSidechainBlockImporter>::new(BlockImporter::new(
		state_handler,
		state_key_repository.clone(),
		top_pool_executor,
		parentchain_block_import_dispatcher,
		ocall_api.clone(),
	));

	let sidechain_block_import_queue = GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT.get()?;

	let sidechain_block_syncer =
		Arc::new(EnclaveSidechainBlockSyncer::new(sidechain_block_importer, ocall_api));
	GLOBAL_SIDECHAIN_BLOCK_SYNCER_COMPONENT.initialize(sidechain_block_syncer.clone());

	let sidechain_block_import_queue_worker =
		Arc::new(EnclaveSidechainBlockImportQueueWorker::new(
			sidechain_block_import_queue,
			sidechain_block_syncer,
		));
	GLOBAL_SIDECHAIN_IMPORT_QUEUE_WORKER_COMPONENT.initialize(sidechain_block_import_queue_worker);

	let block_composer = Arc::new(BlockComposer::new(signer, state_key_repository));
	GLOBAL_SIDECHAIN_BLOCK_COMPOSER_COMPONENT.initialize(block_composer);

	Ok(())
}

pub(crate) fn init_light_client(params: LightClientInitParams<Header>) -> EnclaveResult<Header> {
	let latest_header = itc_parentchain::light_client::io::read_or_init_validator::<Block>(params)?;

	// Initialize the global parentchain block import dispatcher instance.
	let signer = Ed25519Seal::unseal_from_static_file()?;
	let shielding_key_repository = GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT.get()?;

	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
	let stf_executor = GLOBAL_STF_EXECUTOR_COMPONENT.get()?;
	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;
	let top_pool_author = GLOBAL_TOP_POOL_AUTHOR_COMPONENT.get()?;

	let validator_access: Arc<Box<dyn Validator<Block>>> = match params {
		LightClientInitParams::Grandpa { .. } =>
			Arc::new(Box::new(EnclaveValidatorAccessor::default())),
		LightClientInitParams::Parachain { .. } =>
			Arc::new(Box::new(EnclaveValidatorAccessor::default())),
	};

	let genesis_hash = validator_access.execute_on_validator(|v| v.genesis_hash(v.num_relays()))?;

	let extrinsics_factory =
		Arc::new(ExtrinsicsFactory::new(genesis_hash, signer, GLOBAL_NONCE_CACHE.clone()));

	GLOBAL_EXTRINSICS_FACTORY_COMPONENT.initialize(extrinsics_factory.clone());

	let stf_enclave_signer = Arc::new(EnclaveStfEnclaveSigner::new(
		state_handler,
		ocall_api.clone(),
		shielding_key_repository.clone(),
	));
	let indirect_calls_executor = Arc::new(IndirectCallsExecutor::new(
		shielding_key_repository,
		stf_enclave_signer,
		top_pool_author,
	));
	let parentchain_block_importer = ParentchainBlockImporter::new(
		validator_access,
		ocall_api,
		stf_executor,
		extrinsics_factory,
		indirect_calls_executor,
	);
	let parentchain_block_import_queue = BlockImportQueue::<SignedBlock>::default();
	let parentchain_block_import_dispatcher = Arc::new(TriggeredDispatcher::new(
		parentchain_block_importer,
		parentchain_block_import_queue,
	));

	GLOBAL_PARENTCHAIN_IMPORT_DISPATCHER_COMPONENT.initialize(parentchain_block_import_dispatcher);

	Ok(latest_header)
}

pub(crate) fn init_direct_invocation_server(server_addr: String) -> EnclaveResult<()> {
	let rpc_handler = GLOBAL_RPC_WS_HANDLER_COMPONENT.get()?;

	let web_socket_server = create_ws_server(server_addr.as_str(), rpc_handler);

	GLOBAL_WEB_SOCKET_SERVER_COMPONENT.initialize(web_socket_server.clone());

	match web_socket_server.run() {
		Ok(()) => {},
		Err(e) => {
			error!("Web socket server encountered an unexpected error: {:?}", e)
		},
	}

	Ok(())
}

pub(crate) fn init_shard(shard: ShardIdentifier) -> EnclaveResult<()> {
	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
	let _ = state_handler.initialize_shard(shard)?;
	Ok(())
}

/// Initialize the TOP pool author component.
pub fn create_top_pool_author(
	connection_registry: Arc<EnclaveRpcConnectionRegistry>,
	state_handler: Arc<EnclaveStateHandler>,
	ocall_api: Arc<EnclaveOCallApi>,
	shielding_key_repository: Arc<EnclaveShieldingKeyRepository>,
) -> Arc<EnclaveTopPoolAuthor> {
	let response_channel = Arc::new(RpcResponseChannel::default());
	let rpc_responder = Arc::new(EnclaveRpcResponder::new(connection_registry, response_channel));

	let side_chain_api = Arc::new(EnclaveSidechainApi::new());
	let top_pool =
		Arc::new(EnclaveTopPool::create(PoolOptions::default(), side_chain_api, rpc_responder));

	Arc::new(EnclaveTopPoolAuthor::new(
		top_pool,
		AuthorTopFilter {},
		state_handler,
		shielding_key_repository,
		ocall_api,
	))
}
