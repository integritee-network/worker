use crate::rpc;
use derive_more::{Display, From};
use sgx_types::sgx_status_t;

use std::result::Result as StdResult;

pub type Result<T> = StdResult<T, Error>;

#[derive(Debug, Display, From)]
pub enum Error {
	Rpc(rpc::error::Error),
	Codec(codec::Error),
	Rsa(crate::rsa3072::Error),
	ChainStorage(crate::onchain_storage::Error),
	Sgx(sgx_status_t),
}

impl From<Error> for sgx_status_t {
	/// return sgx_status for top level enclave functions
	fn from(error: Error) -> sgx_status_t {
		match error {
			Error::Sgx(status) => status,
			_ => {
				log::warn!("Tried extracting sgx_status from non-sgx error: {:?}", error);
				sgx_status_t::SGX_ERROR_UNEXPECTED
			},
		}
	}
}

impl<T> From<Error> for StdResult<T, Error> {
	fn from(error: Error) -> StdResult<T, Error> {
		Err(error)
	}
}
