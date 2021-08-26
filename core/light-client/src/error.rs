use std::{boxed::Box, string::String};

use sgx_types::sgx_status_t;
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use thiserror_sgx as thiserror;

pub type Result<T> = core::result::Result<T, Error>;

/// Substrate Client error
#[derive(Debug, thiserror::Error)]
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
	#[error(transparent)]
	Storage(#[from] substratee_storage::Error),
	#[error("Validator set mismatch")]
	ValidatorSetMismatch,
	#[error("Invalid ancestry proof")]
	InvalidAncestryProof,
	#[error("No such relay exists")]
	NoSuchRelayExists,
	#[error("Invalid Finality Proof: {0}")]
	InvalidFinalityProof(#[from] JustificationError),
	#[error("Header ancestry mismatch")]
	HeaderAncestryMismatch,
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
