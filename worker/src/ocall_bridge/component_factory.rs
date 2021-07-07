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

use crate::node_api_factory::NodeApiFactory;
use crate::ocall_bridge::attestation_ocall_impl::RemoteAttestationOCallImpl;
use crate::ocall_bridge::bridge_api::{RemoteAttestationOCall, WorkerOnChainOCall};
use crate::ocall_bridge::on_chain_ocall_impl::WorkerOnChainOCallImpl;
use crate::sync_block_gossiper::SyncBlockGossiper;
use std::sync::Arc;

/// Factory trait (abstract factory) that creates instances
/// of all the components of the OCall Bridge
pub trait OCallBridgeComponentFactory {
    /// remote attestation OCall API
    fn get_ra_api(&self) -> Arc<dyn RemoteAttestationOCall>;

    /// on chain OCall API
    fn get_oc_api(&self) -> Arc<dyn WorkerOnChainOCall>;
}

/// Concrete implementation, should be moved out of the OCall Bridge, into the worker
/// since the OCall bridge itself should not know any concrete types to ensure
/// our dependency graph is worker -> ocall bridge
pub struct OCallBridgeComponentFactoryImpl<F, S>
where
    F: NodeApiFactory + 'static,
    S: SyncBlockGossiper + 'static,
{
    node_api_factory: Arc<F>,
    block_gossiper: Arc<S>,
}

impl<F, S> OCallBridgeComponentFactoryImpl<F, S>
where
    F: NodeApiFactory + 'static,
    S: SyncBlockGossiper + 'static,
{
    pub fn new(node_api_factory: Arc<F>, block_gossiper: Arc<S>) -> Self {
        OCallBridgeComponentFactoryImpl {
            node_api_factory,
            block_gossiper,
        }
    }
}

impl<F, S> OCallBridgeComponentFactory for OCallBridgeComponentFactoryImpl<F, S>
where
    F: NodeApiFactory + 'static,
    S: SyncBlockGossiper + 'static,
{
    fn get_ra_api(&self) -> Arc<dyn RemoteAttestationOCall> {
        Arc::new(RemoteAttestationOCallImpl {})
    }

    fn get_oc_api(&self) -> Arc<dyn WorkerOnChainOCall> {
        Arc::new(WorkerOnChainOCallImpl::new(
            self.node_api_factory.clone(),
            self.block_gossiper.clone(),
        ))
    }
}
