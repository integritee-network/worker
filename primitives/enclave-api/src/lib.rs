//! Some definitions and traits that facilitate interaction with the enclave.
//!
//! This serves as a proof of concept on how we could design the interface between the worker and
//! the enclave.
//!
//! Design principle here should be to keep the traits as slim as possible - because then the
//! worker can also define slim interfaces with less demanding trait bounds.
//!
//! This can further be simplified once https://github.com/integritee-network/worker/issues/254
//! is implemented. Then we can replace the several ffi::<enclave_call> and the boilerplate code
//! around it with a simple `fn ecall(call: CallEnum) -> Result<D: Decode>`, which wraps one single
//! ffi function.
//!

use frame_support::ensure;
use sgx_types::{sgx_enclave_id_t, sgx_status_t};

use crate::error::Error;
use codec::Encode;
use frame_support::sp_runtime::app_crypto::sp_core::H256;

use substratee_enclave_api_ffi as ffi;

pub mod error;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Enclave {
    eid: sgx_enclave_id_t,
}

impl Enclave {
    pub fn new(eid: sgx_enclave_id_t) -> Self {
        Enclave { eid }
    }
}

pub type EnclaveResult<T> = Result<T, Error>;

pub trait EnclaveApi: Send + Sync + 'static {
    // Todo: Vec<u8> shall be replaced by D: Decode, E: Encode but this is currently
    // not compatible with the direct_api_server...
    fn rpc(&self, request: Vec<u8>) -> EnclaveResult<Vec<u8>>;
}

pub trait TeeRexApi: Send + Sync + 'static {
    /// Register enclave xt with an empty attestation report.
    fn mock_register_xt(
        &self,
        genesis_hash: H256,
        nonce: u32,
        w_url: &str,
    ) -> EnclaveResult<Vec<u8>>;
}

impl EnclaveApi for Enclave {
    fn rpc(&self, request: Vec<u8>) -> EnclaveResult<Vec<u8>> {
        let mut retval = sgx_status_t::SGX_SUCCESS;
        let response_len = 8192;
        let mut response: Vec<u8> = vec![0u8; response_len as usize];

        let res = unsafe {
            ffi::call_rpc_methods(
                self.eid,
                &mut retval,
                request.as_ptr(),
                request.len() as u32,
                response.as_mut_ptr(),
                response_len,
            )
        };

        ensure!(res == sgx_status_t::SGX_SUCCESS, Error::Sgx(res));
        ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

        Ok(response)
    }
}

impl TeeRexApi for Enclave {
    fn mock_register_xt(
        &self,
        genesis_hash: H256,
        nonce: u32,
        w_url: &str,
    ) -> EnclaveResult<Vec<u8>> {
        let mut retval = sgx_status_t::SGX_SUCCESS;
        let response_len = 8192;
        let mut response: Vec<u8> = vec![0u8; response_len as usize];

        let url = w_url.encode();
        let gen = genesis_hash.as_bytes().to_vec();

        let res = unsafe {
            ffi::mock_register_enclave_xt(
                self.eid,
                &mut retval,
                gen.as_ptr(),
                gen.len() as u32,
                &nonce,
                url.as_ptr(),
                url.len() as u32,
                response.as_mut_ptr(),
                response_len,
            )
        };

        ensure!(res == sgx_status_t::SGX_SUCCESS, Error::Sgx(res));
        ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

        Ok(response)
    }
}
