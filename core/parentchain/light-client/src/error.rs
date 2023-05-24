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

use std::{boxed::Box, string::String};

use sgx_types::sgx_status_t;
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use thiserror_sgx as thiserror;

pub type Result<T> = core::result::Result<T, Error>;

/// Substrate Client error
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum JustificationError {
	#[error("Error decoding justification")]
	JustificationDecode,
	/// Justification for header is correctly encoded, but invalid.
	#[error("bad justification for header: {0}")]
	BadJustification(String),
	#[error("Invalid authorities set")]
	InvalidAuthoritiesSet,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("Genesis not found")]
	NoGenesis,
	#[error(transparent)]
	Storage(#[from] itp_storage::Error),
	#[error("Validator set mismatch")]
	ValidatorSetMismatch,
	#[error("Invalid ancestry proof")]
	InvalidAncestryProof,
	#[error("Invalid Finality Proof: {0}")]
	InvalidFinalityProof(#[from] JustificationError),
	#[error("Header ancestry mismatch")]
	HeaderAncestryMismatch,
	#[error("Poisoned validator lock")]
	PoisonedLock,
	#[error("No Justification found")]
	NoJustificationFound,
	#[error(transparent)]
	Other(#[from] Box<dyn std::error::Error + Sync + Send + 'static>),
}

impl From<std::io::Error> for Error {
	fn from(e: std::io::Error) -> Self {
		Self::Other(e.into())
	}
}

impl From<codec::Error> for Error {
	#[cfg(feature = "std")]
	fn from(e: codec::Error) -> Self {
		Self::Other(e.into())
	}

	#[cfg(not(feature = "std"))]
	fn from(e: codec::Error) -> Self {
		Self::Other(format!("{:?}", e).into())
	}
}

impl From<Error> for sgx_status_t {
	/// return sgx_status for top level enclave functions
	fn from(error: Error) -> sgx_status_t {
		log::warn!("LightClientError into sgx_status_t: {:?}", error);
		sgx_status_t::SGX_ERROR_UNEXPECTED
	}
}
