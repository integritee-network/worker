//! some definitions and traits that facilitate interaction with the enclave.

use sgx_types::{sgx_enclave_id_t, sgx_status_t};
use frame_support::ensure;

use crate::error::Error;

pub mod ffi;
pub mod error;

pub struct Enclave {
	eid: sgx_enclave_id_t
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
				response_len
			)
		};

		ensure!(res == sgx_status_t::SGX_SUCCESS, Error::Sgx(res));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(response)
	}
}