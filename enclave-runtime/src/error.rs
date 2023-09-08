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

use derive_more::From;
use sgx_types::{sgx_quote3_error_t, sgx_status_t};
use std::{boxed::Box, result::Result as StdResult, string::String};

pub type Result<T> = StdResult<T, Error>;

#[derive(Debug, From)]
pub enum Error {
	TopPoolAuthor(itp_top_pool_author::error::Error),
	Codec(codec::Error),
	ComponentContainer(itp_component_container::error::Error),
	Crypto(itp_sgx_crypto::Error),
	ChainStorage(itp_ocall_api::Error),
	ExtrinsicsFactory(itp_extrinsics_factory::error::Error),
	IO(std::io::Error),
	LightClient(itc_parentchain::light_client::error::Error),
	NodeMetadataProvider(itp_node_api::metadata::provider::Error),
	Sgx(sgx_status_t),
	SgxQuote(sgx_quote3_error_t),
	Consensus(its_sidechain::consensus_common::Error),
	Stf(String),
	StfStateHandler(itp_stf_state_handler::error::Error),
	StfExecution(itp_stf_executor::error::Error),
	ParentchainBlockImportDispatch(itc_parentchain::block_import_dispatcher::error::Error),
	ExpectedTriggeredImportDispatcher,
	CouldNotDispatchBlockImport,
	NoIntegriteeParentchainAssigned,
	NoTargetAParentchainAssigned,
	NoTargetBParentchainAssigned,
	ParentChainValidation(itp_storage::error::Error),
	ParentChainSync,
	PrimitivesAccess(itp_primitives_cache::error::Error),
	MutexAccess,
	Attestation(itp_attestation_handler::error::Error),
	Metadata(itp_node_api_metadata::error::Error),
	BufferError(itp_utils::buffer::BufferError),
	Other(Box<dyn std::error::Error>),
}

impl From<Error> for sgx_status_t {
	/// return sgx_status for top level enclave functions
	fn from(error: Error) -> sgx_status_t {
		match error {
			Error::Sgx(status) => status,
			_ => {
				log::error!("Returning error {:?} as sgx unexpected.", error);
				sgx_status_t::SGX_ERROR_UNEXPECTED
			},
		}
	}
}

impl From<Error> for sgx_quote3_error_t {
	/// return sgx_quote error
	fn from(error: Error) -> sgx_quote3_error_t {
		match error {
			Error::SgxQuote(status) => status,
			_ => {
				log::error!("Returning error {:?} as sgx unexpected.", error);
				sgx_quote3_error_t::SGX_QL_ERROR_UNEXPECTED
			},
		}
	}
}

impl<T> From<Error> for StdResult<T, Error> {
	fn from(error: Error) -> StdResult<T, Error> {
		Err(error)
	}
}
