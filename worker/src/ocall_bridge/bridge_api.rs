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

use crate::ocall_bridge::component_factory::OCallBridgeComponentFactory;
use lazy_static::lazy_static;
use log::*;
use parking_lot::RwLock;
use sgx_types::{
    sgx_epid_group_id_t, sgx_platform_info_t, sgx_quote_nonce_t, sgx_quote_sign_type_t,
    sgx_report_t, sgx_spid_t, sgx_status_t, sgx_target_info_t, sgx_update_info_bit_t,
};
use std::sync::Arc;
use std::vec::Vec;

#[cfg(test)]
use mockall::predicate::*;
#[cfg(test)]
use mockall::*;

lazy_static! {
    /// global state for the component factory
    /// access is always routed through 'Bridge', do not use directly!
    static ref COMPONENT_FACTORY: RwLock<Option<Arc<dyn OCallBridgeComponentFactory + Send + Sync>>> =
        RwLock::new(None);
}

/// The Bridge is the static/global interface to inject concrete implementations
/// (or rather the factories for them) - this is done at startup of the worker.
/// On the other side, it is used by the o-call FFI to retrieve the state and forward calls
/// to their respective implementation.
pub struct Bridge;

impl Bridge {
    pub fn get_ra_api() -> Arc<dyn RemoteAttestationOCall> {
        debug!("Requesting RemoteAttestation OCall API instance");

        COMPONENT_FACTORY
            .read()
            .as_ref()
            .expect("Component factory has not been set. Use `initialize()`")
            .get_ra_api()
    }

    pub fn get_oc_api() -> Arc<dyn WorkerOnChainOCall> {
        debug!("Requesting WorkerOnChain OCall API instance");

        COMPONENT_FACTORY
            .read()
            .as_ref()
            .expect("Component factory has not been set. Use `initialize()`")
            .get_oc_api()
    }

    pub fn initialize(component_factory: Arc<dyn OCallBridgeComponentFactory + Send + Sync>) {
        debug!("Initializing OCall bridge with component factory");

        *COMPONENT_FACTORY.write() = Some(component_factory);
    }
}

#[derive(Clone, Eq, PartialEq, Debug, thiserror::Error)]
pub enum OCallBridgeError {
    #[error("GetQuote Error: {0}")]
    GetQuote(sgx_status_t),
    #[error("InitQuote Error: {0}")]
    InitQuote(sgx_status_t),
    #[error("GetUpdateInfo Error: {0}")]
    GetUpdateInfo(sgx_status_t),
    #[error("GetIasSocket Error: {0}")]
    GetIasSocket(String),
    #[error("SendBlockAndConfirmation Error: {0}")]
    SendBlockAndConfirmation(String),
}

#[allow(clippy::from_over_into)]
impl Into<sgx_status_t> for OCallBridgeError {
    fn into(self) -> sgx_status_t {
        match self {
            OCallBridgeError::GetQuote(s) => s,
            OCallBridgeError::InitQuote(s) => s,
            OCallBridgeError::GetUpdateInfo(s) => s,
            OCallBridgeError::GetIasSocket(_) => sgx_status_t::SGX_ERROR_UNEXPECTED,
            OCallBridgeError::SendBlockAndConfirmation(_) => sgx_status_t::SGX_ERROR_UNEXPECTED,
        }
    }
}

pub type OCallBridgeResult<T> = Result<T, OCallBridgeError>;

/// Trait for all the OCalls related to remote attestation
#[cfg_attr(test, automock)]
pub trait RemoteAttestationOCall {
    /// initialize the quote
    fn init_quote(&self) -> OCallBridgeResult<(sgx_target_info_t, sgx_epid_group_id_t)>;

    /// get the intel attestation service socket
    fn get_ias_socket(&self) -> OCallBridgeResult<i32>;

    /// retrieve the quote from intel
    fn get_quote(
        &self,
        revocation_list: Vec<u8>,
        report: sgx_report_t,
        quote_type: sgx_quote_sign_type_t,
        spid: sgx_spid_t,
        quote_nonce: sgx_quote_nonce_t,
    ) -> OCallBridgeResult<(sgx_report_t, Vec<u8>)>;

    /// --
    fn get_update_info(
        &self,
        platform_blob: sgx_platform_info_t,
        enclave_trusted: i32,
    ) -> OCallBridgeResult<sgx_update_info_bit_t>;
}

/// Trait for all the OCalls related to on-chain operations
#[cfg_attr(test, automock)]
pub trait WorkerOnChainOCall {
    fn worker_request(&self, request: Vec<u8>) -> OCallBridgeResult<Vec<u8>>;

    fn send_block_and_confirmation(
        &self,
        confirmations: Vec<u8>,
        signed_blocks: Vec<u8>,
    ) -> OCallBridgeResult<()>;
}
