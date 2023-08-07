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

use crate::{
	initialization::parentchain::{
		parachain::FullParachainHandler, solochain::FullSolochainHandler,
	},
	ocall::OcallApi,
	rpc::rpc_response_channel::RpcResponseChannel,
	tls_ra::seal_handler::SealHandler,
};
use ita_sgx_runtime::Runtime;
use ita_stf::{Getter, State as StfState, Stf, TrustedCallSigned};
use itc_direct_rpc_server::{
	rpc_connection_registry::ConnectionRegistry, rpc_responder::RpcResponder,
	rpc_watch_extractor::RpcWatchExtractor, rpc_ws_handler::RpcWsHandler,
};
use itc_parentchain::{
	block_import_dispatcher::{
		immediate_dispatcher::ImmediateDispatcher, triggered_dispatcher::TriggeredDispatcher,
		BlockImportDispatcher,
	},
	block_importer::ParentchainBlockImporter,
	indirect_calls_executor::{
		filter_metadata::{EventCreator, ShieldFundsAndInvokeFilter},
		parentchain_parser::ParentchainExtrinsicParser,
		IndirectCallsExecutor,
	},
	light_client::{
		concurrent_access::ValidatorAccessor, io::LightClientStateSealSync,
		light_validation::LightValidation, light_validation_state::LightValidationState,
	},
};
use itc_tls_websocket_server::{
	config_provider::FromFileConfigProvider, ws_server::TungsteniteWsServer, ConnectionToken,
};
use itp_attestation_handler::IntelAttestationHandler;
use itp_component_container::ComponentContainer;
use itp_extrinsics_factory::ExtrinsicsFactory;
use itp_import_queue::ImportQueue;
use itp_node_api::{
	api_client::PairSignature,
	metadata::{provider::NodeMetadataRepository, NodeMetadata},
};
use itp_nonce_cache::NonceCache;
use itp_sgx_crypto::{key_repository::KeyRepository, Aes, AesSeal, Ed25519Seal, Rsa3072Seal};
use itp_stf_executor::{
	enclave_signer::StfEnclaveSigner, executor::StfExecutor, getter_executor::GetterExecutor,
	state_getter::StfStateGetter,
};
use itp_stf_primitives::types::Hash;
use itp_stf_state_handler::{
	file_io::sgx::SgxStateFileIo, state_initializer::StateInitializer,
	state_snapshot_repository::StateSnapshotRepository, StateHandler,
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
};
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;
use sgx_tstd::vec::Vec;
use sp_core::{ed25519, ed25519::Pair};

pub type EnclaveParentchainSigner =
	itp_node_api::api_client::StaticExtrinsicSigner<Pair, PairSignature>;

pub type EnclaveGetter = Getter;
pub type EnclaveTrustedCallSigned = TrustedCallSigned;
pub type EnclaveStf = Stf<EnclaveTrustedCallSigned, EnclaveGetter, StfState, Runtime>;
pub type EnclaveStateKeyRepository = KeyRepository<Aes, AesSeal>;
pub type EnclaveShieldingKeyRepository = KeyRepository<Rsa3072KeyPair, Rsa3072Seal>;
pub type EnclaveSigningKeyRepository = KeyRepository<ed25519::Pair, Ed25519Seal>;
pub type EnclaveStateFileIo = SgxStateFileIo<EnclaveStateKeyRepository, StfState>;
pub type EnclaveStateSnapshotRepository = StateSnapshotRepository<EnclaveStateFileIo>;
pub type EnclaveStateObserver = StateObserver<StfState>;
pub type EnclaveStateInitializer =
	StateInitializer<StfState, EnclaveStf, EnclaveShieldingKeyRepository>;
pub type EnclaveStateHandler =
	StateHandler<EnclaveStateSnapshotRepository, EnclaveStateObserver, EnclaveStateInitializer>;
pub type EnclaveGetterExecutor = GetterExecutor<EnclaveStateObserver, StfStateGetter<EnclaveStf>>;
pub type EnclaveOCallApi = OcallApi;
pub type EnclaveNodeMetadataRepository = NodeMetadataRepository<NodeMetadata>;
pub type EnclaveStfExecutor =
	StfExecutor<EnclaveOCallApi, EnclaveStateHandler, EnclaveNodeMetadataRepository, EnclaveStf>;
pub type EnclaveStfEnclaveSigner = StfEnclaveSigner<
	EnclaveOCallApi,
	EnclaveStateObserver,
	EnclaveShieldingKeyRepository,
	EnclaveStf,
	EnclaveTopPoolAuthor,
>;
pub type EnclaveAttestationHandler =
	IntelAttestationHandler<EnclaveOCallApi, EnclaveSigningKeyRepository>;

pub type EnclaveRpcConnectionRegistry = ConnectionRegistry<Hash, ConnectionToken>;
pub type EnclaveRpcWsHandler =
	RpcWsHandler<RpcWatchExtractor<Hash>, EnclaveRpcConnectionRegistry, Hash>;
pub type EnclaveWebSocketServer = TungsteniteWsServer<EnclaveRpcWsHandler, FromFileConfigProvider>;
pub type EnclaveRpcResponder = RpcResponder<EnclaveRpcConnectionRegistry, Hash, RpcResponseChannel>;
pub type EnclaveSidechainApi = SidechainApi<ParentchainBlock>;

// Parentchain types
pub type EnclaveLightClientSeal =
	LightClientStateSealSync<ParentchainBlock, LightValidationState<ParentchainBlock>>;
pub type EnclaveExtrinsicsFactory =
	ExtrinsicsFactory<EnclaveParentchainSigner, NonceCache, EnclaveNodeMetadataRepository>;
pub type EnclaveIndirectCallsExecutor = IndirectCallsExecutor<
	EnclaveShieldingKeyRepository,
	EnclaveStfEnclaveSigner,
	EnclaveTopPoolAuthor,
	EnclaveNodeMetadataRepository,
	ShieldFundsAndInvokeFilter<ParentchainExtrinsicParser>,
	EventCreator,
>;
pub type EnclaveValidatorAccessor = ValidatorAccessor<
	LightValidation<ParentchainBlock, EnclaveOCallApi>,
	ParentchainBlock,
	EnclaveLightClientSeal,
>;
pub type EnclaveParentchainBlockImporter = ParentchainBlockImporter<
	ParentchainBlock,
	EnclaveValidatorAccessor,
	EnclaveStfExecutor,
	EnclaveExtrinsicsFactory,
	EnclaveIndirectCallsExecutor,
>;
pub type EnclaveParentchainBlockImportQueue = ImportQueue<SignedParentchainBlock>;
// Should not be a Vec<Vec<u8>>
pub type EnclaveParentchainEventImportQueue = ImportQueue<Vec<u8>>;
pub type EnclaveTriggeredParentchainBlockImportDispatcher = TriggeredDispatcher<
	EnclaveParentchainBlockImporter,
	EnclaveParentchainBlockImportQueue,
	EnclaveParentchainEventImportQueue,
>;

pub type EnclaveImmediateParentchainBlockImportDispatcher =
	ImmediateDispatcher<EnclaveParentchainBlockImporter>;

pub type EnclaveParentchainBlockImportDispatcher = BlockImportDispatcher<
	EnclaveTriggeredParentchainBlockImportDispatcher,
	EnclaveImmediateParentchainBlockImportDispatcher,
>;

/// Sidechain types
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
	EnclaveStateHandler,
	EnclaveStateKeyRepository,
	EnclaveTopPoolAuthor,
	EnclaveTriggeredParentchainBlockImportDispatcher,
>;
pub type EnclaveSidechainBlockImportQueue = ImportQueue<SignedSidechainBlock>;
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
pub type EnclaveSealHandler = SealHandler<
	EnclaveShieldingKeyRepository,
	EnclaveStateKeyRepository,
	EnclaveStateHandler,
	EnclaveLightClientSeal,
>;
pub type EnclaveOffchainWorkerExecutor = itc_offchain_worker_executor::executor::Executor<
	ParentchainBlock,
	EnclaveTopPoolAuthor,
	EnclaveStfExecutor,
	EnclaveStateHandler,
	EnclaveValidatorAccessor,
	EnclaveExtrinsicsFactory,
	EnclaveStf,
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

/// Signing key repository
pub static GLOBAL_SIGNING_KEY_REPOSITORY_COMPONENT: ComponentContainer<
	EnclaveSigningKeyRepository,
> = ComponentContainer::new("Signing key repository");

/// Light client db seal.
pub static GLOBAL_LIGHT_CLIENT_SEAL: ComponentContainer<EnclaveLightClientSeal> =
	ComponentContainer::new("EnclaveLightClientSealSync");

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

/// attestation handler
pub static GLOBAL_ATTESTATION_HANDLER_COMPONENT: ComponentContainer<EnclaveAttestationHandler> =
	ComponentContainer::new("Attestation handler");

/// Parentchain component instances
///-------------------------------------------------------------------------------------------------

/// Solochain Handler.
pub static GLOBAL_FULL_SOLOCHAIN_HANDLER_COMPONENT: ComponentContainer<FullSolochainHandler> =
	ComponentContainer::new("full solochain handler");

pub static GLOBAL_FULL_PARACHAIN_HANDLER_COMPONENT: ComponentContainer<FullParachainHandler> =
	ComponentContainer::new("full parachain handler");

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
