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

use crate::ocall_bridge::attestation_ocall_impl::RemoteAttestationOCallImpl;
use crate::ocall_bridge::bridge_api::RemoteAttestationOCall;
use std::sync::Arc;

/// Factory trait (abstract factory) that creates instances
/// of all the components of the OCall Bridge
pub trait OCallBridgeComponentFactory {
    /// remote attestation OCall API
    fn get_ra_api(&self) -> Arc<dyn RemoteAttestationOCall>;
}

/// Concrete implementation, should be moved out of the OCall Bridge, into the worker
/// since the OCall bridge itself should not know any concrete types to ensure
/// our dependency graph is worker -> ocall bridge
pub struct OCallBridgeComponentFactoryImpl;

impl OCallBridgeComponentFactory for OCallBridgeComponentFactoryImpl {
    fn get_ra_api(&self) -> Arc<dyn RemoteAttestationOCall> {
        Arc::new(RemoteAttestationOCallImpl {})
    }
}
