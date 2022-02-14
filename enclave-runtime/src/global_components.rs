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

use crate::ocall::OcallApi;
use ita_stf::Hash;
use itc_direct_rpc_server::{
	rpc_connection_registry::ConnectionRegistry, rpc_watch_extractor::RpcWatchExtractor,
	rpc_ws_handler::RpcWsHandler,
};
use itc_parentchain::{
	block_import_dispatcher::triggered_dispatcher::TriggeredDispatcher,
	block_importer::ParentchainBlockImporter, indirect_calls_executor::IndirectCallsExecutor,
	light_client::ValidatorAccessor,
};
use itc_tls_websocket_server::connection::TungsteniteWsConnection;
use itp_block_import_queue::BlockImportQueue;
use itp_component_container::ComponentContainer;
use itp_extrinsics_factory::ExtrinsicsFactory;
use itp_nonce_cache::NonceCache;
use itp_sgx_crypto::Aes;
use itp_stf_executor::executor::StfExecutor;
use itp_stf_state_handler::GlobalFileStateHandler;
use itp_types::{Block as ParentchainBlock, SignedBlock as SignedParentchainBlock};
use its_sidechain::{
	aura::block_importer::BlockImporter as SidechainBlockImporter,
	block_composer::BlockComposer,
	consensus_common::{BlockImportQueueWorker, PeerBlockSync},
	primitives::{
		traits::SignedBlock as SignedSidechainBlockTrait,
		types::SignedBlock as SignedSidechainBlock,
	},
	state::SidechainDB,
	top_pool_executor::TopPoolOperationHandler,
	top_pool_rpc_author::{
		author::{Author, AuthorTopFilter},
		pool_types::BPool,
	},
};
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;
use sgx_externalities::SgxExternalities;
use sp_core::ed25519::Pair;

pub type EnclaveStateHandler = GlobalFileStateHandler;
pub type EnclaveOCallApi = OcallApi;
pub type EnclaveStfExecutor = StfExecutor<EnclaveOCallApi, EnclaveStateHandler, SgxExternalities>;
pub type EnclaveExtrinsicsFactory = ExtrinsicsFactory<Pair, NonceCache>;
pub type EnclaveIndirectCallsExecutor = IndirectCallsExecutor<Rsa3072KeyPair, EnclaveStfExecutor>;
pub type EnclaveValidatorAccessor = ValidatorAccessor<ParentchainBlock>;
pub type EnclaveParentChainBlockImporter = ParentchainBlockImporter<
	ParentchainBlock,
	EnclaveValidatorAccessor,
	EnclaveOCallApi,
	EnclaveStfExecutor,
	EnclaveExtrinsicsFactory,
	EnclaveIndirectCallsExecutor,
>;
pub type EnclaveParentchainBlockImportQueue = BlockImportQueue<SignedParentchainBlock>;
pub type EnclaveParentchainBlockImportDispatcher =
	TriggeredDispatcher<EnclaveParentChainBlockImporter, EnclaveParentchainBlockImportQueue>;
pub type EnclaveRpcWsHandler = RpcWsHandler<
	RpcWatchExtractor<Hash>,
	ConnectionRegistry<Hash, TungsteniteWsConnection>,
	Hash,
	TungsteniteWsConnection,
>;

/// Sidechain types
pub type EnclaveSidechainState =
	SidechainDB<<SignedSidechainBlock as SignedSidechainBlockTrait>::Block, SgxExternalities>;
pub type EnclaveRpcAuthor =
	Author<BPool, AuthorTopFilter, EnclaveStateHandler, Rsa3072KeyPair, EnclaveOCallApi>;
pub type EnclaveTopPoolOperationHandler = TopPoolOperationHandler<
	ParentchainBlock,
	SignedSidechainBlock,
	EnclaveRpcAuthor,
	EnclaveStfExecutor,
>;
pub type EnclaveSidechainBlockComposer =
	BlockComposer<ParentchainBlock, SignedSidechainBlock, Pair, Aes>;
pub type EnclaveSidechainBlockImporter = SidechainBlockImporter<
	Pair,
	ParentchainBlock,
	SignedSidechainBlock,
	EnclaveOCallApi,
	EnclaveSidechainState,
	EnclaveStateHandler,
	Aes,
	EnclaveTopPoolOperationHandler,
	EnclaveParentchainBlockImportDispatcher,
>;
pub type EnclaveSidechainBlockImportQueue = BlockImportQueue<SignedSidechainBlock>;
pub type EnclaveSidechainBlockSyncer = PeerBlockSync<
	ParentchainBlock,
	SignedSidechainBlock,
	EnclaveSidechainBlockImporter,
	EnclaveOCallApi,
>;
pub type EnclaveSidechainBlockImportQueueWorker = BlockImportQueueWorker<
	ParentchainBlock,
	SignedSidechainBlock,
	EnclaveSidechainBlockImportQueue,
	EnclaveSidechainBlockSyncer,
>;

/// Base component instances
///-------------------------------------------------------------------------------------------------

/// STF executor.
pub static GLOBAL_STF_EXECUTOR_COMPONENT: ComponentContainer<EnclaveStfExecutor> =
	ComponentContainer::new();

/// O-Call API
pub static GLOBAL_OCALL_API_COMPONENT: ComponentContainer<EnclaveOCallApi> =
	ComponentContainer::new();

/// State handler.
pub static GLOBAL_STATE_HANDLER_COMPONENT: ComponentContainer<EnclaveStateHandler> =
	ComponentContainer::new();

/// Parentchain component instances
///-------------------------------------------------------------------------------------------------

/// Parentchain import dispatcher.
pub static GLOBAL_PARENTCHAIN_IMPORT_DISPATCHER_COMPONENT: ComponentContainer<
	EnclaveParentchainBlockImportDispatcher,
> = ComponentContainer::new();

/// Extrinsics factory.
pub static GLOBAL_EXTRINSICS_FACTORY_COMPONENT: ComponentContainer<EnclaveExtrinsicsFactory> =
	ComponentContainer::new();

/// Sidechain component instances
///-------------------------------------------------------------------------------------------------

/// Enclave RPC WS handler.
pub static GLOBAL_RPC_WS_HANDLER_COMPONENT: ComponentContainer<EnclaveRpcWsHandler> =
	ComponentContainer::new();

/// Sidechain import queue.
pub static GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT: ComponentContainer<
	EnclaveSidechainBlockImportQueue,
> = ComponentContainer::new();

/// Sidechain import queue worker - processes the import queue.
pub static GLOBAL_SIDECHAIN_IMPORT_QUEUE_WORKER_COMPONENT: ComponentContainer<
	EnclaveSidechainBlockImportQueueWorker,
> = ComponentContainer::new();

/// Sidechain block composer.
pub static GLOBAL_SIDECHAIN_BLOCK_COMPOSER_COMPONENT: ComponentContainer<
	EnclaveSidechainBlockComposer,
> = ComponentContainer::new();

/// Sidechain block syncer.
pub static GLOBAL_SIDECHAIN_BLOCK_SYNCER_COMPONENT: ComponentContainer<
	EnclaveSidechainBlockSyncer,
> = ComponentContainer::new();

/// Sidechain RPC (top pool) author.
pub static GLOBAL_RPC_AUTHOR_COMPONENT: ComponentContainer<EnclaveRpcAuthor> =
	ComponentContainer::new();

/// Sidechain top pool operation handler.
pub static GLOBAL_TOP_POOL_OPERATION_HANDLER_COMPONENT: ComponentContainer<
	EnclaveTopPoolOperationHandler,
> = ComponentContainer::new();
