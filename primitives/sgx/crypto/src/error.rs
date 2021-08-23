use derive_more::{Display, From};
use sgx_types::sgx_status_t;
use std::prelude::v1::Box;

#[derive(Debug, Display, From)]
pub enum Error {
	IO(std::io::Error),
	InvalidNonceKeyLength,
	Codec(codec::Error),
	Other(Box<dyn std::error::Error>),
}

pub type Result<T> = core::result::Result<T, Error>;

impl From<Error> for sgx_status_t {
	/// return sgx_status for top level enclave functions
	fn from(error: Error) -> sgx_status_t {
		log::warn!("Transform non-sgx-error into `SGX_ERROR_UNEXPECTED`: {:?}", error);
		sgx_status_t::SGX_ERROR_UNEXPECTED
	}
}
