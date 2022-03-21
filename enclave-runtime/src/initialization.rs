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
		EnclaveSidechainBlockImportQueue, EnclaveSidechainBlockImportQueueWorker,
		EnclaveSidechainBlockImporter, EnclaveSidechainBlockSyncer, EnclaveStfExecutor,
		EnclaveTopPoolOperationHandler, EnclaveValidatorAccessor,
		GLOBAL_EXTRINSICS_FACTORY_COMPONENT, GLOBAL_OCALL_API_COMPONENT,
		GLOBAL_PARENTCHAIN_IMPORT_DISPATCHER_COMPONENT, GLOBAL_RPC_AUTHOR_COMPONENT,
		GLOBAL_RPC_WS_HANDLER_COMPONENT, GLOBAL_SIDECHAIN_BLOCK_COMPOSER_COMPONENT,
		GLOBAL_SIDECHAIN_BLOCK_SYNCER_COMPONENT, GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT,
		GLOBAL_SIDECHAIN_IMPORT_QUEUE_WORKER_COMPONENT, GLOBAL_STATE_HANDLER_COMPONENT,
		GLOBAL_STF_EXECUTOR_COMPONENT, GLOBAL_TOP_POOL_OPERATION_HANDLER_COMPONENT,
	},
	ocall::OcallApi,
	rpc::worker_api_direct::public_api_rpc_handler,
	Hash,
};
use base58::ToBase58;
use codec::Encode;
use itc_direct_rpc_server::{
	create_determine_watch, rpc_connection_registry::ConnectionRegistry,
	rpc_ws_handler::RpcWsHandler,
};
use itc_parentchain::{
	block_import_dispatcher::triggered_dispatcher::TriggeredDispatcher,
	block_importer::ParentchainBlockImporter,
	indirect_calls_executor::IndirectCallsExecutor,
	light_client::{concurrent_access::ValidatorAccess, LightClientState},
};
use itc_tls_websocket_server::{connection::TungsteniteWsConnection, run_ws_server};
use itp_block_import_queue::BlockImportQueue;
use itp_component_container::{ComponentGetter, ComponentInitializer};
use itp_extrinsics_factory::ExtrinsicsFactory;
use itp_nonce_cache::GLOBAL_NONCE_CACHE;
use itp_primitives_cache::GLOBAL_PRIMITIVES_CACHE;
use itp_sgx_crypto::{aes, ed25519, rsa3072, AesSeal, Ed25519Seal, Rsa3072Seal};
use itp_sgx_io::SealedIO;
use itp_stf_state_handler::{query_shard_state::QueryShardState, GlobalFileStateHandler};
use itp_storage::StorageProof;
use itp_types::{Block, Header, SignedBlock};
use its_sidechain::{
	aura::block_importer::BlockImporter, block_composer::BlockComposer,
	top_pool_executor::TopPoolOperationHandler,
};
use log::*;
use sp_core::crypto::Pair;
use sp_finality_grandpa::VersionedAuthorityList;
use std::{string::String, sync::Arc};

pub(crate) fn init_enclave(mu_ra_url: String, untrusted_worker_url: String) -> EnclaveResult<()> {
	// Initialize the logging environment in the enclave.
	env_logger::init();

	ed25519::create_sealed_if_absent().map_err(Error::Crypto)?;
	let signer = Ed25519Seal::unseal().map_err(Error::Crypto)?;
	info!("[Enclave initialized] Ed25519 prim raw : {:?}", signer.public().0);

	rsa3072::create_sealed_if_absent()?;

	// Create the aes key that is used for state encryption such that a key is always present in tests.
	// It will be overwritten anyway if mutual remote attastation is performed with the primary worker.
	aes::create_sealed_if_absent().map_err(Error::Crypto)?;

	let state_handler = Arc::new(GlobalFileStateHandler);
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

	let shielding_key = Rsa3072Seal::unseal()?;
	let watch_extractor = Arc::new(create_determine_watch::<Hash>());
	let connection_registry = Arc::new(ConnectionRegistry::<Hash, TungsteniteWsConnection>::new());

	let rpc_author = its_sidechain::top_pool_rpc_author::initializer::create_top_pool_rpc_author(
		connection_registry.clone(),
		state_handler,
		ocall_api,
		shielding_key,
	);
	GLOBAL_RPC_AUTHOR_COMPONENT.initialize(rpc_author.clone());

	let io_handler = public_api_rpc_handler(rpc_author.clone());
	let rpc_handler = Arc::new(RpcWsHandler::new(io_handler, watch_extractor, connection_registry));
	GLOBAL_RPC_WS_HANDLER_COMPONENT.initialize(rpc_handler);

	let sidechain_block_import_queue = Arc::new(EnclaveSidechainBlockImportQueue::default());
	GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT.initialize(sidechain_block_import_queue.clone());

	Ok(())
}

pub(crate) fn init_enclave_sidechain_components() -> EnclaveResult<()> {
	let stf_executor = GLOBAL_STF_EXECUTOR_COMPONENT.get().ok_or_else(|| {
		error!("Failed to retrieve global STF executor component (maybe it is not initialized?)");
		Error::ComponentNotInitialized
	})?;

	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get().ok_or_else(|| {
		error!("Failed to retrieve global state handler component (maybe it is not initialized?)");
		Error::ComponentNotInitialized
	})?;

	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get().ok_or_else(|| {
		error!("Failed to retrieve global O-call API component (maybe it is not initialized?)");
		Error::ComponentNotInitialized
	})?;

	let rpc_author = GLOBAL_RPC_AUTHOR_COMPONENT.get().ok_or_else(|| {
		error!("Failed to retrieve global RPC AUTHOR component (maybe it is not initialized?)");
		Error::ComponentNotInitialized
	})?;

	let top_pool_operation_handler =
		Arc::new(EnclaveTopPoolOperationHandler::new(rpc_author.clone(), stf_executor.clone()));
	GLOBAL_TOP_POOL_OPERATION_HANDLER_COMPONENT.initialize(top_pool_operation_handler);

	let top_pool_executor = Arc::<EnclaveTopPoolOperationHandler>::new(
		TopPoolOperationHandler::new(rpc_author, stf_executor),
	);

	let parentchain_block_import_dispatcher = GLOBAL_PARENTCHAIN_IMPORT_DISPATCHER_COMPONENT
		.get().ok_or_else(|| {
		error!("Failed to retrieve global parentchain import dispatcher component (maybe it is not initialized?)");
		Error::ComponentNotInitialized
	})?;

	let signer = Ed25519Seal::unseal()?;
	let state_key = AesSeal::unseal()?;

	let sidechain_block_importer = Arc::<EnclaveSidechainBlockImporter>::new(BlockImporter::new(
		state_handler,
		state_key,
		signer,
		top_pool_executor,
		parentchain_block_import_dispatcher,
		ocall_api.clone(),
	));

	let sidechain_block_import_queue = GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT.get().ok_or_else(|| {
		error!("Failed to retrieve global sidechain block import queue component (maybe it is not initialized?)");
		Error::ComponentNotInitialized
	})?;

	let sidechain_block_syncer =
		Arc::new(EnclaveSidechainBlockSyncer::new(sidechain_block_importer, ocall_api));
	GLOBAL_SIDECHAIN_BLOCK_SYNCER_COMPONENT.initialize(sidechain_block_syncer.clone());

	let sidechain_block_import_queue_worker =
		Arc::new(EnclaveSidechainBlockImportQueueWorker::new(
			sidechain_block_import_queue,
			sidechain_block_syncer,
		));
	GLOBAL_SIDECHAIN_IMPORT_QUEUE_WORKER_COMPONENT.initialize(sidechain_block_import_queue_worker);

	let block_composer = Arc::new(BlockComposer::new(signer, state_key));
	GLOBAL_SIDECHAIN_BLOCK_COMPOSER_COMPONENT.initialize(block_composer);

	Ok(())
}

pub(crate) fn init_light_client(
	genesis_header: Header,
	authorities: VersionedAuthorityList,
	storage_proof: StorageProof,
) -> EnclaveResult<Header> {
	let latest_header = itc_parentchain::light_client::io::read_or_init_validator::<Block>(
		genesis_header,
		authorities,
		storage_proof,
	)?;

	// Initialize the global parentchain block import dispatcher instance.
	let signer = Ed25519Seal::unseal()?;
	let shielding_key = Rsa3072Seal::unseal()?;

	let stf_executor = GLOBAL_STF_EXECUTOR_COMPONENT.get().ok_or_else(|| {
		error!("Failed to retrieve global STF executor (maybe it is not initialized?)");
		Error::ComponentNotInitialized
	})?;

	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get().ok_or_else(|| {
		error!("Failed to retrieve global O-call API (maybe it is not initialized?)");
		Error::ComponentNotInitialized
	})?;

	let validator_access = Arc::new(EnclaveValidatorAccessor::default());
	let genesis_hash = validator_access.execute_on_validator(|v| v.genesis_hash(v.num_relays()))?;

	let extrinsics_factory =
		Arc::new(ExtrinsicsFactory::new(genesis_hash, signer, GLOBAL_NONCE_CACHE.clone()));

	GLOBAL_EXTRINSICS_FACTORY_COMPONENT.initialize(extrinsics_factory.clone());

	let indirect_calls_executor =
		Arc::new(IndirectCallsExecutor::new(shielding_key, stf_executor.clone()));
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
	let rpc_handler = GLOBAL_RPC_WS_HANDLER_COMPONENT.get().ok_or_else(|| {
		error!("Failed to retrieve global RPC handler (maybe it is not initialized?)");
		Error::ComponentNotInitialized
	})?;

	run_ws_server(server_addr.as_str(), rpc_handler);

	Ok(())
}
