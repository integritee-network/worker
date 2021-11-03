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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use sgx_types::sgx_status_t;
use std::{boxed::Box, format};

pub type Result<T> = core::result::Result<T, Error>;

/// STF-Executor error
#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("Trusted operation has invalid signature")]
	OperationHasInvalidSignature,
	#[error("SGX error, status: {0}")]
	Sgx(sgx_status_t),
	#[error("State handling error: {0}")]
	StateHandler(#[from] itp_stf_state_handler::error::Error),
	#[error("STF error: {0}")]
	Stf(ita_stf::StfError),
	#[error("Storage verified error: {0}")]
	StorageVerified(itp_storage_verifier::Error),
	#[error(transparent)]
	Other(#[from] Box<dyn std::error::Error + Sync + Send + 'static>),
}

impl From<sgx_status_t> for Error {
	fn from(sgx_status: sgx_status_t) -> Self {
		Self::Sgx(sgx_status)
	}
}

impl From<codec::Error> for Error {
	fn from(e: codec::Error) -> Self {
		Self::Other(format!("{:?}", e).into())
	}
}

impl From<ita_stf::StfError> for Error {
	fn from(error: ita_stf::StfError) -> Self {
		Self::Stf(error)
	}
}

impl From<itp_storage_verifier::Error> for Error {
	fn from(error: itp_storage_verifier::Error) -> Self {
		Self::StorageVerified(error)
	}
}
