/*
    Copyright 2019 Supercomputing Systems AG
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

use crate::direct_invocation::direct_invocation_ocall::DirectInvocationOCall;
use crate::direct_invocation::watch_list_service::WatchList;
use crate::node_api_factory::CreateNodeApi;
use crate::ocall_bridge::bridge_api::{
    DirectInvocationBridge, GetOCallBridgeComponents, IpfsBridge, RemoteAttestationBridge,
    WorkerOnChainBridge,
};
use crate::ocall_bridge::ipfs_ocall::IpfsOCall;
use crate::ocall_bridge::remote_attestation_ocall::RemoteAttestationOCall;
use crate::ocall_bridge::worker_on_chain_ocall::WorkerOnChainOCall;
use crate::sync_block_gossiper::GossipBlocks;
use std::sync::Arc;

/// Concrete implementation, should be moved out of the OCall Bridge, into the worker
/// since the OCall bridge itself should not know any concrete types to ensure
/// our dependency graph is worker -> ocall bridge
pub struct OCallBridgeComponentFactory<N, B, W> {
    node_api_factory: Arc<N>,
    block_gossiper: Arc<B>,
    watch_list: Arc<W>,
}

impl<N, B, W> OCallBridgeComponentFactory<N, B, W> {
    pub fn new(node_api_factory: Arc<N>, block_gossiper: Arc<B>, watch_list: Arc<W>) -> Self {
        OCallBridgeComponentFactory {
            node_api_factory,
            block_gossiper,
            watch_list,
        }
    }
}

impl<N, B, W> GetOCallBridgeComponents for OCallBridgeComponentFactory<N, B, W>
where
    N: CreateNodeApi + 'static,
    B: GossipBlocks + 'static,
    W: WatchList + 'static,
{
    fn get_ra_api(&self) -> Arc<dyn RemoteAttestationBridge> {
        Arc::new(RemoteAttestationOCall {})
    }

    fn get_oc_api(&self) -> Arc<dyn WorkerOnChainBridge> {
        Arc::new(WorkerOnChainOCall::new(
            self.node_api_factory.clone(),
            self.block_gossiper.clone(),
        ))
    }

    fn get_ipfs_api(&self) -> Arc<dyn IpfsBridge> {
        Arc::new(IpfsOCall {})
    }

    fn get_direct_invocation_api(&self) -> Arc<dyn DirectInvocationBridge> {
        Arc::new(DirectInvocationOCall::new(self.watch_list.clone()))
    }
}
