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
	node_api_factory::CreateNodeApi,
	ocall_bridge::{
		bridge_api::{
			GetOCallBridgeComponents, IpfsBridge, RemoteAttestationBridge, SidechainBridge,
			WorkerOnChainBridge,
		},
		ipfs_ocall::IpfsOCall,
		remote_attestation_ocall::RemoteAttestationOCall,
		sidechain_ocall::SidechainOCall,
		worker_on_chain_ocall::WorkerOnChainOCall,
	},
	sync_block_gossiper::GossipBlocks,
};
use itp_enclave_api::remote_attestation::RemoteAttestationCallBacks;
use its_primitives::types::SignedBlock as SignedSidechainBlock;
use its_storage::BlockStorage;
use std::sync::Arc;

/// Concrete implementation, should be moved out of the OCall Bridge, into the worker
/// since the OCall bridge itself should not know any concrete types to ensure
/// our dependency graph is worker -> ocall bridge
pub struct OCallBridgeComponentFactory<N, B, E, D> {
	node_api_factory: Arc<N>,
	block_gossiper: Arc<B>,
	enclave_api: Arc<E>,
	block_storage: Arc<D>,
}

impl<N, B, E, D> OCallBridgeComponentFactory<N, B, E, D> {
	pub fn new(
		node_api_factory: Arc<N>,
		block_gossiper: Arc<B>,
		enclave_api: Arc<E>,
		block_storage: Arc<D>,
	) -> Self {
		OCallBridgeComponentFactory { node_api_factory, block_gossiper, enclave_api, block_storage }
	}
}

impl<N, B, E, D> GetOCallBridgeComponents for OCallBridgeComponentFactory<N, B, E, D>
where
	N: CreateNodeApi + 'static,
	B: GossipBlocks + 'static,
	E: RemoteAttestationCallBacks + 'static,
	D: BlockStorage<SignedSidechainBlock> + 'static,
{
	fn get_ra_api(&self) -> Arc<dyn RemoteAttestationBridge> {
		Arc::new(RemoteAttestationOCall::new(self.enclave_api.clone()))
	}

	fn get_sidechain_api(&self) -> Arc<dyn SidechainBridge> {
		Arc::new(SidechainOCall::new(self.block_gossiper.clone(), self.block_storage.clone()))
	}

	fn get_oc_api(&self) -> Arc<dyn WorkerOnChainBridge> {
		Arc::new(WorkerOnChainOCall::new(self.node_api_factory.clone()))
	}

	fn get_ipfs_api(&self) -> Arc<dyn IpfsBridge> {
		Arc::new(IpfsOCall {})
	}
}
