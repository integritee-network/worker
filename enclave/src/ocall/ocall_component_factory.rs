/*
    Copyright 2019 Supercomputing Systems AG

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

use crate::ocall::attestation_ocall::EnclaveAttestationOCallApiImpl;
use crate::ocall::ocall_api::EnclaveAttestationOCallApi;
use std::sync::Arc;

/// Abstract factory trait for OCall components
pub trait OCallComponentFactoryTrait<A: EnclaveAttestationOCallApi> {
    fn get_attestation_api() -> Arc<A>;
}

/// Concrete implementation of the factory, producing components for live system (i.e. not mocks)
pub struct OCallComponentFactory {}

impl OCallComponentFactoryTrait<EnclaveAttestationOCallApiImpl> for OCallComponentFactory {
    fn get_attestation_api() -> Arc<EnclaveAttestationOCallApiImpl> {
        Arc::new(EnclaveAttestationOCallApiImpl {})
    }
}
