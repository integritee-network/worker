use derive_more::{Display, From};
use sgx_types::sgx_status_t;
use crate::rpc;

#[derive(Debug, Display, From)]
pub enum Error {
	Rpc(rpc::error::Error),
	Codec(codec::Error),
	Sgx(sgx_status_t)
}

impl From<Error> for sgx_status_t {
	/// return sgx_status for top level enclave functions
	fn from(error: Error) -> sgx_status_t {
		match error {
			Error::Sgx(status) => status,
			_=>  {
				log::warn!("Tried extracting sgx_status from non-sgx error: {:?}", error);
				sgx_status_t::SGX_ERROR_UNEXPECTED
			}
		}
	}
}

impl<T> From<Error> for Result<T, Error> {
	fn from(error: Error) -> Result<T, Error> {
		Err(error)
	}
}