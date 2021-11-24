/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

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

use derive_more::{Display, From};
use sgx_types::sgx_status_t;
use std::{boxed::Box, result::Result as StdResult, string::String};

pub type Result<T> = StdResult<T, Error>;

#[derive(Debug, Display, From)]
pub enum Error {
	Rpc(its_sidechain::top_pool_rpc_author::error::Error),
	Codec(codec::Error),
	ComponentNotInitialized,
	Crypto(itp_sgx_crypto::Error),
	ChainStorage(itp_storage_verifier::Error),
	ExtrinsicsFactory(itp_extrinsics_factory::error::Error),
	IO(std::io::Error),
	LightClient(itc_parentchain::light_client::error::Error),
	Sgx(sgx_status_t),
	Consensus(its_sidechain::consensus_common::Error),
	Stf(String),
	StfStateHandler(itp_stf_state_handler::error::Error),
	StfExecution(itp_stf_executor::error::Error),
	ParentchainBlockImportDispatch(itc_parentchain::block_import_dispatcher::error::Error),
	MutexAccess,
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
