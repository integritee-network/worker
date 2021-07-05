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

pub trait OCallBridgeComponentFactory<A: RemoteAttestationOCall> {
    fn get_ra_api() -> Arc<A>;
}

pub struct OCallBridgeComponentFactoryImpl {}

impl OCallBridgeComponentFactory<RemoteAttestationOCallImpl> for OCallBridgeComponentFactoryImpl {
    fn get_ra_api() -> Arc<RemoteAttestationOCallImpl> {
        Arc::new(RemoteAttestationOCallImpl {})
    }
}
