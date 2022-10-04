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

//! Defines all concrete types and global components of the enclave.
//!
//! This allows the crates themselves to stay as generic as possible
//! and ensures that the global instances are initialized once.

use crate::{ocall::OcallApi, rpc::rpc_response_channel::RpcResponseChannel};
use ita_stf::{Hash, State as StfState};
use itc_direct_rpc_server::{
	rpc_connection_registry::ConnectionRegistry, rpc_responder::RpcResponder,
	rpc_watch_extractor::RpcWatchExtractor, rpc_ws_handler::RpcWsHandler,
};
use itc_parentchain::{
	block_import_dispatcher::{
		immediate_dispatcher::ImmediateDispatcher, triggered_dispatcher::TriggeredDispatcher,
	},
	block_importer::ParentchainBlockImporter,
	indirect_calls_executor::IndirectCallsExecutor,
	light_client::{
		concurrent_access::ValidatorAccessor, io::LightClientStateSeal,
		light_validation::LightValidation, light_validation_state::LightValidationState,
	},
};
use itc_tls_websocket_server::{
	config_provider::FromFileConfigProvider, ws_server::TungsteniteWsServer, ConnectionToken,
};
use itp_block_import_queue::BlockImportQueue;
use itp_component_container::ComponentContainer;
use itp_extrinsics_factory::ExtrinsicsFactory;
use itp_node_api::metadata::{provider::NodeMetadataRepository, NodeMetadata};
use itp_nonce_cache::NonceCache;
use itp_sgx_crypto::{key_repository::KeyRepository, Aes, AesSeal, Rsa3072Seal};
use itp_sgx_externalities::SgxExternalities;
use itp_stf_executor::{
	enclave_signer::StfEnclaveSigner, executor::StfExecutor, getter_executor::GetterExecutor,
	state_getter::StfStateGetter,
};
use itp_stf_state_handler::{
	file_io::sgx::SgxStateFileIo, state_snapshot_repository::StateSnapshotRepository, StateHandler,
};
use itp_stf_state_observer::state_observer::StateObserver;
use itp_top_pool::basic_pool::BasicPool;
use itp_top_pool_author::{
	api::SidechainApi,
	author::{Author, AuthorTopFilter},
};
use itp_types::{Block as ParentchainBlock, SignedBlock as SignedParentchainBlock};
use its_primitives::{
	traits::{Block as SidechainBlockTrait, SignedBlock as SignedSidechainBlockTrait},
	types::block::SignedBlock as SignedSidechainBlock,
};
use its_sidechain::{
	aura::block_importer::BlockImporter as SidechainBlockImporter,
	block_composer::BlockComposer,
	consensus_common::{BlockImportConfirmationHandler, BlockImportQueueWorker, PeerBlockSync},
	state::SidechainDB,
};
use primitive_types::H256;
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;
use sp_core::ed25519::Pair;

pub type EnclaveStateKeyRepository = KeyRepository<Aes, AesSeal>;
pub type EnclaveShieldingKeyRepository = KeyRepository<Rsa3072KeyPair, Rsa3072Seal>;
pub type EnclaveStateFileIo = SgxStateFileIo<EnclaveStateKeyRepository>;
pub type EnclaveStateSnapshotRepository =
	StateSnapshotRepository<EnclaveStateFileIo, StfState, H256>;
pub type EnclaveStateObserver = StateObserver<StfState>;
pub type EnclaveStateHandler = StateHandler<EnclaveStateSnapshotRepository, EnclaveStateObserver>;
pub type EnclaveGetterExecutor = GetterExecutor<EnclaveStateObserver, StfStateGetter>;
pub type EnclaveOCallApi = OcallApi;
pub type EnclaveNodeMetadataRepository = NodeMetadataRepository<NodeMetadata>;
pub type EnclaveStfExecutor =
	StfExecutor<EnclaveOCallApi, EnclaveStateHandler, EnclaveNodeMetadataRepository>;
pub type EnclaveStfEnclaveSigner =
	StfEnclaveSigner<EnclaveOCallApi, EnclaveStateObserver, EnclaveShieldingKeyRepository>;
pub type EnclaveExtrinsicsFactory =
	ExtrinsicsFactory<Pair, NonceCache, EnclaveNodeMetadataRepository>;
pub type EnclaveIndirectCallsExecutor = IndirectCallsExecutor<
	EnclaveShieldingKeyRepository,
	EnclaveStfEnclaveSigner,
	EnclaveTopPoolAuthor,
	EnclaveNodeMetadataRepository,
>;
pub type EnclaveValidatorAccessor = ValidatorAccessor<
	LightValidation<ParentchainBlock, EnclaveOCallApi>,
	ParentchainBlock,
	LightClientStateSeal<ParentchainBlock, LightValidationState<ParentchainBlock>>,
>;
pub type EnclaveParentchainBlockImporter = ParentchainBlockImporter<
	ParentchainBlock,
	EnclaveValidatorAccessor,
	EnclaveStfExecutor,
	EnclaveExtrinsicsFactory,
	EnclaveIndirectCallsExecutor,
>;
pub type EnclaveParentchainBlockImportQueue = BlockImportQueue<SignedParentchainBlock>;
pub type EnclaveTriggeredParentchainBlockImportDispatcher =
	TriggeredDispatcher<EnclaveParentchainBlockImporter, EnclaveParentchainBlockImportQueue>;
pub type EnclaveImmediateParentchainBlockImportDispatcher =
	ImmediateDispatcher<EnclaveParentchainBlockImporter>;

pub type EnclaveRpcConnectionRegistry = ConnectionRegistry<Hash, ConnectionToken>;
pub type EnclaveRpcWsHandler =
	RpcWsHandler<RpcWatchExtractor<Hash>, EnclaveRpcConnectionRegistry, Hash>;
pub type EnclaveWebSocketServer = TungsteniteWsServer<EnclaveRpcWsHandler, FromFileConfigProvider>;
pub type EnclaveRpcResponder = RpcResponder<EnclaveRpcConnectionRegistry, Hash, RpcResponseChannel>;
pub type EnclaveSidechainApi = SidechainApi<ParentchainBlock>;

/// Sidechain types
pub type EnclaveSidechainState =
	SidechainDB<<SignedSidechainBlock as SignedSidechainBlockTrait>::Block, SgxExternalities>;
pub type EnclaveTopPool = BasicPool<EnclaveSidechainApi, ParentchainBlock, EnclaveRpcResponder>;

pub type EnclaveTopPoolAuthor = Author<
	EnclaveTopPool,
	AuthorTopFilter,
	EnclaveStateHandler,
	EnclaveShieldingKeyRepository,
	EnclaveOCallApi,
>;
pub type EnclaveSidechainBlockComposer =
	BlockComposer<ParentchainBlock, SignedSidechainBlock, Pair, EnclaveStateKeyRepository>;
pub type EnclaveSidechainBlockImporter = SidechainBlockImporter<
	Pair,
	ParentchainBlock,
	SignedSidechainBlock,
	EnclaveOCallApi,
	EnclaveSidechainState,
	EnclaveStateHandler,
	EnclaveStateKeyRepository,
	EnclaveTopPoolAuthor,
	EnclaveTriggeredParentchainBlockImportDispatcher,
>;
pub type EnclaveSidechainBlockImportQueue = BlockImportQueue<SignedSidechainBlock>;
pub type EnclaveBlockImportConfirmationHandler = BlockImportConfirmationHandler<
	ParentchainBlock,
	<<SignedSidechainBlock as SignedSidechainBlockTrait>::Block as SidechainBlockTrait>::HeaderType,
	EnclaveNodeMetadataRepository,
	EnclaveExtrinsicsFactory,
	EnclaveValidatorAccessor,
>;
pub type EnclaveSidechainBlockSyncer = PeerBlockSync<
	ParentchainBlock,
	SignedSidechainBlock,
	EnclaveSidechainBlockImporter,
	EnclaveOCallApi,
	EnclaveBlockImportConfirmationHandler,
>;
pub type EnclaveSidechainBlockImportQueueWorker = BlockImportQueueWorker<
	ParentchainBlock,
	SignedSidechainBlock,
	EnclaveSidechainBlockImportQueue,
	EnclaveSidechainBlockSyncer,
>;

/// Base component instances
///-------------------------------------------------------------------------------------------------

/// State key repository
pub static GLOBAL_STATE_KEY_REPOSITORY_COMPONENT: ComponentContainer<EnclaveStateKeyRepository> =
	ComponentContainer::new("State key repository");

/// Shielding key repository
pub static GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT: ComponentContainer<
	EnclaveShieldingKeyRepository,
> = ComponentContainer::new("Shielding key repository");

/// STF executor.
pub static GLOBAL_STF_EXECUTOR_COMPONENT: ComponentContainer<EnclaveStfExecutor> =
	ComponentContainer::new("STF executor");

/// O-Call API
pub static GLOBAL_OCALL_API_COMPONENT: ComponentContainer<EnclaveOCallApi> =
	ComponentContainer::new("O-call API");

/// Trusted Web-socket server
pub static GLOBAL_WEB_SOCKET_SERVER_COMPONENT: ComponentContainer<EnclaveWebSocketServer> =
	ComponentContainer::new("Web-socket server");

/// State handler.
pub static GLOBAL_STATE_HANDLER_COMPONENT: ComponentContainer<EnclaveStateHandler> =
	ComponentContainer::new("state handler");

/// State observer.
pub static GLOBAL_STATE_OBSERVER_COMPONENT: ComponentContainer<EnclaveStateObserver> =
	ComponentContainer::new("state observer");

/// TOP pool author.
pub static GLOBAL_TOP_POOL_AUTHOR_COMPONENT: ComponentContainer<EnclaveTopPoolAuthor> =
	ComponentContainer::new("top_pool_author");

/// Parentchain component instances
///-------------------------------------------------------------------------------------------------

/// Triggered parentchain block import dispatcher.
pub static GLOBAL_TRIGGERED_PARENTCHAIN_IMPORT_DISPATCHER_COMPONENT: ComponentContainer<
	EnclaveTriggeredParentchainBlockImportDispatcher,
> = ComponentContainer::new("triggered parentchain import dispatcher");

/// Immediate parentchain block import dispatcher.
pub static GLOBAL_IMMEDIATE_PARENTCHAIN_IMPORT_DISPATCHER_COMPONENT: ComponentContainer<
	EnclaveImmediateParentchainBlockImportDispatcher,
> = ComponentContainer::new("immediate parentchain import dispatcher");

/// Parentchain block validator accessor.
pub static GLOBAL_PARENTCHAIN_BLOCK_VALIDATOR_ACCESS_COMPONENT: ComponentContainer<
	EnclaveValidatorAccessor,
> = ComponentContainer::new("parentchain block validator accessor");

/// Extrinsics factory.
pub static GLOBAL_EXTRINSICS_FACTORY_COMPONENT: ComponentContainer<EnclaveExtrinsicsFactory> =
	ComponentContainer::new("extrinsics_factory");

pub static GLOBAL_NODE_METADATA_REPOSITORY_COMPONENT: ComponentContainer<
	EnclaveNodeMetadataRepository,
> = ComponentContainer::new("node metadata repository");

/// Sidechain component instances
///-------------------------------------------------------------------------------------------------

/// Enclave RPC WS handler.
pub static GLOBAL_RPC_WS_HANDLER_COMPONENT: ComponentContainer<EnclaveRpcWsHandler> =
	ComponentContainer::new("rpc_ws_handler");

/// Sidechain import queue.
pub static GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT: ComponentContainer<
	EnclaveSidechainBlockImportQueue,
> = ComponentContainer::new("sidechain_import_queue");

/// Sidechain import queue worker - processes the import queue.
pub static GLOBAL_SIDECHAIN_IMPORT_QUEUE_WORKER_COMPONENT: ComponentContainer<
	EnclaveSidechainBlockImportQueueWorker,
> = ComponentContainer::new("sidechain_import_queue_worker");

/// Sidechain block composer.
pub static GLOBAL_SIDECHAIN_BLOCK_COMPOSER_COMPONENT: ComponentContainer<
	EnclaveSidechainBlockComposer,
> = ComponentContainer::new("sidechain_block_composer");

/// Sidechain block syncer.
pub static GLOBAL_SIDECHAIN_BLOCK_SYNCER_COMPONENT: ComponentContainer<
	EnclaveSidechainBlockSyncer,
> = ComponentContainer::new("sidechain_block_syncer");
