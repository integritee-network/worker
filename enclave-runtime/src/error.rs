use crate::rpc;
use derive_more::{Display, From};
use sgx_types::sgx_status_t;
use std::{prelude::v1::Box, result::Result as StdResult, string::String};

pub type Result<T> = StdResult<T, Error>;

#[derive(Debug, Display, From)]
pub enum Error {
	Rpc(rpc::error::Error),
	Codec(codec::Error),
	Crypto(itp_sgx_crypto::Error),
	Rsa(crate::rsa3072::Error),
	ChainStorage(itp_storage_verifier::Error),
	IO(std::io::Error),
	LightClient(itc_light_client::error::Error),
	Sgx(sgx_status_t),
	Stf(String),
	Other(Box<dyn std::error::Error>),
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
