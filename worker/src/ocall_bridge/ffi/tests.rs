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

#[cfg(test)]
use super::*;
use crate::ocall_bridge::bridge_api::{MockRemoteAttestationOCall, RemoteAttestationOCall};
use crate::ocall_bridge::component_factory::OCallBridgeComponentFactory;
use std::sync::Arc;

#[test]
fn init_quote_sets_results() {
    let mut ra_ocall_api_mock = MockRemoteAttestationOCall::new();
    ra_ocall_api_mock
        .expect_init_quote()
        .times(1)
        .returning(|| (sgx_status_t::SGX_SUCCESS, dummy_target_info(), [8u8; 4]));

    Bridge::initialize(Arc::new(MockComponentFactoryImpl::new(Arc::new(
        ra_ocall_api_mock,
    ))));

    let mut ti: sgx_target_info_t = sgx_target_info_t::default();
    let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();

    let ret_status = ocall_sgx_init_quote(
        &mut ti as *mut sgx_target_info_t,
        &mut eg as *mut sgx_epid_group_id_t,
    );

    Bridge::clear();

    assert_eq!(ret_status, sgx_status_t::SGX_SUCCESS);
    assert_eq!(eg, [8u8; 4])
}

fn dummy_target_info() -> sgx_target_info_t {
    sgx_target_info_t::default()
}

pub struct MockComponentFactoryImpl {
    ra_ocall: Arc<dyn RemoteAttestationOCall + Send + Sync>,
}

impl MockComponentFactoryImpl {
    pub fn new(ra_ocall: Arc<dyn RemoteAttestationOCall + Send + Sync>) -> Self {
        MockComponentFactoryImpl { ra_ocall }
    }
}

impl OCallBridgeComponentFactory for MockComponentFactoryImpl {
    fn get_ra_api(&self) -> Arc<dyn RemoteAttestationOCall> {
        self.ra_ocall.clone()
    }
}
