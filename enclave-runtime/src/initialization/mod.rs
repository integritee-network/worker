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

pub mod global_components;
pub mod parentchain;

use crate::{
	error::{Error, Result as EnclaveResult},
	initialization::global_components::{
		EnclaveBlockImportConfirmationHandler, EnclaveGetterExecutor, EnclaveOCallApi,
		EnclaveRpcConnectionRegistry, EnclaveRpcResponder, EnclaveShieldingKeyRepository,
		EnclaveSidechainApi, EnclaveSidechainBlockImportQueue,
		EnclaveSidechainBlockImportQueueWorker, EnclaveSidechainBlockImporter,
		EnclaveSidechainBlockSyncer, EnclaveStateFileIo, EnclaveStateHandler,
		EnclaveStateInitializer, EnclaveStateKeyRepository, EnclaveStateObserver,
		EnclaveStateSnapshotRepository, EnclaveStfEnclaveSigner, EnclaveTopPool,
		EnclaveTopPoolAuthor, GLOBAL_ATTESTATION_HANDLER_COMPONENT, GLOBAL_OCALL_API_COMPONENT,
		GLOBAL_RPC_WS_HANDLER_COMPONENT, GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT,
		GLOBAL_SIDECHAIN_BLOCK_COMPOSER_COMPONENT, GLOBAL_SIDECHAIN_BLOCK_SYNCER_COMPONENT,
		GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT, GLOBAL_SIDECHAIN_IMPORT_QUEUE_WORKER_COMPONENT,
		GLOBAL_STATE_HANDLER_COMPONENT, GLOBAL_STATE_KEY_REPOSITORY_COMPONENT,
		GLOBAL_STATE_OBSERVER_COMPONENT, GLOBAL_TOP_POOL_AUTHOR_COMPONENT,
		GLOBAL_WEB_SOCKET_SERVER_COMPONENT,
	},
	ocall::OcallApi,
	rpc::{rpc_response_channel::RpcResponseChannel, worker_api_direct::public_api_rpc_handler},
	utils::{
		get_extrinsic_factory_from_solo_or_parachain,
		get_node_metadata_repository_from_solo_or_parachain,
		get_triggered_dispatcher_from_solo_or_parachain,
		get_validator_accessor_from_solo_or_parachain,
	},
	Hash,
};
use base58::ToBase58;
use codec::Encode;
use itc_direct_rpc_server::{
	create_determine_watch, rpc_connection_registry::ConnectionRegistry,
	rpc_ws_handler::RpcWsHandler,
};
use itc_tls_websocket_server::{
	certificate_generation::ed25519_self_signed_certificate, create_ws_server, ConnectionToken,
	WebSocketServer,
};
use itp_attestation_handler::IntelAttestationHandler;
use itp_component_container::{ComponentGetter, ComponentInitializer};
use itp_primitives_cache::GLOBAL_PRIMITIVES_CACHE;
use itp_settings::files::STATE_SNAPSHOTS_CACHE_SIZE;
use itp_sgx_crypto::{aes, ed25519, rsa3072, AesSeal, Ed25519Seal, Rsa3072Seal};
use itp_sgx_io::StaticSealedIO;
use itp_stf_state_handler::{
	handle_state::HandleState, query_shard_state::QueryShardState,
	state_snapshot_repository::VersionedStateAccess,
	state_snapshot_repository_loader::StateSnapshotRepositoryLoader, StateHandler,
};
use itp_top_pool::pool::Options as PoolOptions;
use itp_top_pool_author::author::AuthorTopFilter;
use itp_types::ShardIdentifier;
use its_sidechain::block_composer::BlockComposer;
use log::*;
use sp_core::crypto::Pair;
use std::{collections::HashMap, string::String, sync::Arc};

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

	let state_file_io = Arc::new(EnclaveStateFileIo::new(state_key_repository));
	let state_initializer =
		Arc::new(EnclaveStateInitializer::new(shielding_key_repository.clone()));
	let state_snapshot_repository_loader = StateSnapshotRepositoryLoader::<
		EnclaveStateFileIo,
		EnclaveStateInitializer,
	>::new(state_file_io, state_initializer.clone());

	let state_snapshot_repository =
		state_snapshot_repository_loader.load_snapshot_repository(STATE_SNAPSHOTS_CACHE_SIZE)?;
	let state_observer = initialize_state_observer(&state_snapshot_repository)?;
	GLOBAL_STATE_OBSERVER_COMPONENT.initialize(state_observer.clone());

	let state_handler = Arc::new(StateHandler::load_from_repository(
		state_snapshot_repository,
		state_observer.clone(),
		state_initializer,
	)?);

	GLOBAL_STATE_HANDLER_COMPONENT.initialize(state_handler.clone());

	let ocall_api = Arc::new(OcallApi);
	GLOBAL_OCALL_API_COMPONENT.initialize(ocall_api.clone());

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
		ocall_api.clone(),
		shielding_key_repository,
	);
	GLOBAL_TOP_POOL_AUTHOR_COMPONENT.initialize(top_pool_author.clone());

	let getter_executor = Arc::new(EnclaveGetterExecutor::new(state_observer));
	let io_handler = public_api_rpc_handler(top_pool_author, getter_executor);
	let rpc_handler = Arc::new(RpcWsHandler::new(io_handler, watch_extractor, connection_registry));
	GLOBAL_RPC_WS_HANDLER_COMPONENT.initialize(rpc_handler);

	let sidechain_block_import_queue = Arc::new(EnclaveSidechainBlockImportQueue::default());
	GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT.initialize(sidechain_block_import_queue);

	let attestation_handler = Arc::new(IntelAttestationHandler::new(ocall_api));
	GLOBAL_ATTESTATION_HANDLER_COMPONENT.initialize(attestation_handler);

	Ok(())
}

fn initialize_state_observer(
	snapshot_repository: &EnclaveStateSnapshotRepository,
) -> EnclaveResult<Arc<EnclaveStateObserver>> {
	let shards = snapshot_repository.list_shards()?;
	let mut states_map = HashMap::<
		ShardIdentifier,
		<EnclaveStateSnapshotRepository as VersionedStateAccess>::StateType,
	>::new();
	for shard in shards.into_iter() {
		let state = snapshot_repository.load_latest(&shard)?;
		states_map.insert(shard, state);
	}
	Ok(Arc::new(EnclaveStateObserver::from_map(states_map)))
}

pub(crate) fn init_enclave_sidechain_components() -> EnclaveResult<()> {
	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;
	let top_pool_author = GLOBAL_TOP_POOL_AUTHOR_COMPONENT.get()?;

	let parentchain_block_import_dispatcher = get_triggered_dispatcher_from_solo_or_parachain()?;

	let state_key_repository = GLOBAL_STATE_KEY_REPOSITORY_COMPONENT.get()?;

	let signer = Ed25519Seal::unseal_from_static_file()?;

	let sidechain_block_importer = Arc::new(EnclaveSidechainBlockImporter::new(
		state_handler,
		state_key_repository.clone(),
		top_pool_author,
		parentchain_block_import_dispatcher,
		ocall_api.clone(),
	));

	let sidechain_block_import_queue = GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT.get()?;
	let metadata_repository = get_node_metadata_repository_from_solo_or_parachain()?;
	let extrinsics_factory = get_extrinsic_factory_from_solo_or_parachain()?;
	let validator_accessor = get_validator_accessor_from_solo_or_parachain()?;

	let sidechain_block_import_confirmation_handler =
		Arc::new(EnclaveBlockImportConfirmationHandler::new(
			metadata_repository,
			extrinsics_factory,
			validator_accessor,
		));

	let sidechain_block_syncer = Arc::new(EnclaveSidechainBlockSyncer::new(
		sidechain_block_importer,
		ocall_api,
		sidechain_block_import_confirmation_handler,
	));
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

pub(crate) fn init_direct_invocation_server(server_addr: String) -> EnclaveResult<()> {
	let rpc_handler = GLOBAL_RPC_WS_HANDLER_COMPONENT.get()?;
	let signing = Ed25519Seal::unseal_from_static_file()?;

	let cert =
		ed25519_self_signed_certificate(signing, "Enclave").map_err(|e| Error::Other(e.into()))?;

	// Serialize certificate(s) and private key to PEM.
	// PEM format is needed as a certificate chain can only be serialized into PEM.
	let pem_serialized = cert.serialize_pem().map_err(|e| Error::Other(e.into()))?;
	let private_key = cert.serialize_private_key_pem();

	let web_socket_server =
		create_ws_server(server_addr.as_str(), &private_key, &pem_serialized, rpc_handler);

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
