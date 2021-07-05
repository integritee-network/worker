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

use sgx_types::{
    sgx_epid_group_id_t, sgx_platform_info_t, sgx_quote_nonce_t, sgx_quote_sign_type_t,
    sgx_report_t, sgx_spid_t, sgx_status_t, sgx_target_info_t, sgx_update_info_bit_t,
};
use std::vec::Vec;

pub trait RemoteAttestationOCall {
    fn init_quote(&self) -> (sgx_status_t, sgx_target_info_t, sgx_epid_group_id_t);

    fn get_ias_socket(&self) -> i32;

    fn get_quote(
        &self,
        revocation_list: Vec<u8>,
        report: sgx_report_t,
        quote_type: sgx_quote_sign_type_t,
        spid: sgx_spid_t,
        quote_nonce: sgx_quote_nonce_t,
    ) -> (sgx_status_t, sgx_report_t, Vec<u8>);

    fn get_update_info(
        &self,
        platform_blob: sgx_platform_info_t,
        enclave_trusted: i32,
    ) -> (sgx_status_t, sgx_update_info_bit_t);
}
