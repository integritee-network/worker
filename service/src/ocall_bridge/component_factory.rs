/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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
	globals::tokio_handle::GetTokioHandle,
	ocall_bridge::{
		bridge_api::{
			GetOCallBridgeComponents, IpfsBridge, MetricsBridge, RemoteAttestationBridge,
			SidechainBridge, WorkerOnChainBridge,
		},
		ipfs_ocall::IpfsOCall,
		metrics_ocall::MetricsOCall,
		remote_attestation_ocall::RemoteAttestationOCall,
		sidechain_ocall::SidechainOCall,
		worker_on_chain_ocall::WorkerOnChainOCall,
	},
	prometheus_metrics::ReceiveEnclaveMetrics,
	sync_block_broadcaster::BroadcastBlocks,
	worker_peers_updater::UpdateWorkerPeers,
};
use itp_enclave_api::remote_attestation::RemoteAttestationCallBacks;
use itp_node_api::node_api_factory::CreateNodeApi;
use itp_types::parentchain::Hash;
use its_peer_fetch::FetchBlocksFromPeer;
use its_primitives::types::block::SignedBlock as SignedSidechainBlock;
use its_storage::BlockStorage;
use std::sync::Arc;
use substrate_api_client::{GetStorage, SubmitAndWatch, SubmitExtrinsic};

/// Concrete implementation, should be moved out of the OCall Bridge, into the worker
/// since the OCall bridge itself should not know any concrete types to ensure
/// our dependency graph is worker -> ocall bridge
pub struct OCallBridgeComponentFactory<
	IntegriteeNodeApiFactory,
	TargetANodeApiFactory,
	TargetBNodeApiFactory,
	Broadcaster,
	EnclaveApi,
	Storage,
	PeerUpdater,
	PeerBlockFetcher,
	TokioHandle,
	MetricsReceiver,
> {
	integritee_rpc_api_factory: Arc<IntegriteeNodeApiFactory>,
	target_a_parentchain_rpc_api_factory: Option<Arc<TargetANodeApiFactory>>,
	target_b_parentchain_rpc_api_factory: Option<Arc<TargetBNodeApiFactory>>,
	block_broadcaster: Arc<Broadcaster>,
	enclave_api: Arc<EnclaveApi>,
	block_storage: Arc<Storage>,
	peer_updater: Arc<PeerUpdater>,
	peer_block_fetcher: Arc<PeerBlockFetcher>,
	tokio_handle: Arc<TokioHandle>,
	metrics_receiver: Arc<MetricsReceiver>,
}

impl<
		IntegriteeNodeApiFactory,
		TargetANodeApiFactory,
		TargetBNodeApiFactory,
		Broadcaster,
		EnclaveApi,
		Storage,
		PeerUpdater,
		PeerBlockFetcher,
		TokioHandle,
		MetricsReceiver,
	>
	OCallBridgeComponentFactory<
		IntegriteeNodeApiFactory,
		TargetANodeApiFactory,
		TargetBNodeApiFactory,
		Broadcaster,
		EnclaveApi,
		Storage,
		PeerUpdater,
		PeerBlockFetcher,
		TokioHandle,
		MetricsReceiver,
	>
{
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		integritee_rpc_api_factory: Arc<IntegriteeNodeApiFactory>,
		target_a_parentchain_rpc_api_factory: Option<Arc<TargetANodeApiFactory>>,
		target_b_parentchain_rpc_api_factory: Option<Arc<TargetBNodeApiFactory>>,
		block_broadcaster: Arc<Broadcaster>,
		enclave_api: Arc<EnclaveApi>,
		block_storage: Arc<Storage>,
		peer_updater: Arc<PeerUpdater>,
		peer_block_fetcher: Arc<PeerBlockFetcher>,
		tokio_handle: Arc<TokioHandle>,
		metrics_receiver: Arc<MetricsReceiver>,
	) -> Self {
		OCallBridgeComponentFactory {
			integritee_rpc_api_factory,
			target_a_parentchain_rpc_api_factory,
			target_b_parentchain_rpc_api_factory,
			block_broadcaster,
			enclave_api,
			block_storage,
			peer_updater,
			peer_block_fetcher,
			tokio_handle,
			metrics_receiver,
		}
	}
}

impl<
		IntegriteeNodeApiFactory,
		TargetANodeApiFactory,
		TargetBNodeApiFactory,
		Broadcaster,
		EnclaveApi,
		Storage,
		PeerUpdater,
		PeerBlockFetcher,
		TokioHandle,
		MetricsReceiver,
	> GetOCallBridgeComponents
	for OCallBridgeComponentFactory<
		IntegriteeNodeApiFactory,
		TargetANodeApiFactory,
		TargetBNodeApiFactory,
		Broadcaster,
		EnclaveApi,
		Storage,
		PeerUpdater,
		PeerBlockFetcher,
		TokioHandle,
		MetricsReceiver,
	> where
	IntegriteeNodeApiFactory: CreateNodeApi + 'static,
	IntegriteeNodeApiFactory::Api: GetStorage<Hash = Hash> + SubmitAndWatch + SubmitExtrinsic,
	TargetANodeApiFactory: CreateNodeApi + 'static,
	TargetANodeApiFactory::Api: GetStorage<Hash = Hash> + SubmitAndWatch + SubmitExtrinsic,
	TargetBNodeApiFactory: CreateNodeApi + 'static,
	TargetBNodeApiFactory::Api: GetStorage<Hash = Hash> + SubmitAndWatch + SubmitExtrinsic,
	Broadcaster: BroadcastBlocks + 'static,
	EnclaveApi: RemoteAttestationCallBacks + 'static,
	Storage: BlockStorage<SignedSidechainBlock> + 'static,
	PeerUpdater: UpdateWorkerPeers + 'static,
	PeerBlockFetcher: FetchBlocksFromPeer<SignedBlockType = SignedSidechainBlock> + 'static,
	TokioHandle: GetTokioHandle + 'static,
	MetricsReceiver: ReceiveEnclaveMetrics + 'static,
{
	fn get_ra_api(&self) -> Arc<dyn RemoteAttestationBridge> {
		Arc::new(RemoteAttestationOCall::new(self.enclave_api.clone()))
	}

	fn get_sidechain_api(&self) -> Arc<dyn SidechainBridge> {
		Arc::new(SidechainOCall::new(
			self.block_broadcaster.clone(),
			self.block_storage.clone(),
			self.peer_updater.clone(),
			self.peer_block_fetcher.clone(),
			self.tokio_handle.clone(),
		))
	}

	fn get_oc_api(&self) -> Arc<dyn WorkerOnChainBridge> {
		Arc::new(WorkerOnChainOCall::new(
			self.integritee_rpc_api_factory.clone(),
			self.target_a_parentchain_rpc_api_factory.clone(),
			self.target_b_parentchain_rpc_api_factory.clone(),
		))
	}

	fn get_ipfs_api(&self) -> Arc<dyn IpfsBridge> {
		Arc::new(IpfsOCall {})
	}

	fn get_metrics_api(&self) -> Arc<dyn MetricsBridge> {
		Arc::new(MetricsOCall::new(self.metrics_receiver.clone()))
	}
}
