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
	direct_invocation::{
		direct_invocation_ocall::DirectInvocationOCall, watch_list_service::WatchList,
	},
	node_api_factory::CreateNodeApi,
	ocall_bridge::{
		bridge_api::{
			DirectInvocationBridge, GetOCallBridgeComponents, IpfsBridge, RemoteAttestationBridge,
			WorkerOnChainBridge,
		},
		ipfs_ocall::IpfsOCall,
		remote_attestation_ocall::RemoteAttestationOCall,
		worker_on_chain_ocall::WorkerOnChainOCall,
	},
	sidechain_storage::BlockStorage,
	sync_block_gossiper::GossipBlocks,
};
use itp_enclave_api::remote_attestation::RemoteAttestationCallBacks;
use its_primitives::types::SignedBlock as SignedSidechainBlock;
use std::sync::Arc;

/// Concrete implementation, should be moved out of the OCall Bridge, into the worker
/// since the OCall bridge itself should not know any concrete types to ensure
/// our dependency graph is worker -> ocall bridge
pub struct OCallBridgeComponentFactory<N, B, W, E, D> {
	node_api_factory: Arc<N>,
	block_gossiper: Arc<B>,
	watch_list: Arc<W>,
	enclave_api: Arc<E>,
	block_storage: Arc<D>,
}

impl<N, B, W, E, D> OCallBridgeComponentFactory<N, B, W, E, D> {
	pub fn new(
		node_api_factory: Arc<N>,
		block_gossiper: Arc<B>,
		watch_list: Arc<W>,
		enclave_api: Arc<E>,
		block_storage: Arc<D>,
	) -> Self {
		OCallBridgeComponentFactory {
			node_api_factory,
			block_gossiper,
			watch_list,
			enclave_api,
			block_storage,
		}
	}
}

impl<N, B, W, E, D> GetOCallBridgeComponents for OCallBridgeComponentFactory<N, B, W, E, D>
where
	N: CreateNodeApi + 'static,
	B: GossipBlocks + 'static,
	W: WatchList + 'static,
	E: RemoteAttestationCallBacks + 'static,
	D: BlockStorage<SignedSidechainBlock> + 'static,
{
	fn get_ra_api(&self) -> Arc<dyn RemoteAttestationBridge> {
		Arc::new(RemoteAttestationOCall::new(self.enclave_api.clone()))
	}

	fn get_oc_api(&self) -> Arc<dyn WorkerOnChainBridge> {
		Arc::new(WorkerOnChainOCall::new(
			self.node_api_factory.clone(),
			self.block_gossiper.clone(),
			self.block_storage.clone(),
		))
	}

	fn get_ipfs_api(&self) -> Arc<dyn IpfsBridge> {
		Arc::new(IpfsOCall {})
	}

	fn get_direct_invocation_api(&self) -> Arc<dyn DirectInvocationBridge> {
		Arc::new(DirectInvocationOCall::new(self.watch_list.clone()))
	}
}
