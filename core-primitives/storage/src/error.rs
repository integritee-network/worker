#[cfg(all(not(feature = "std"), feature = "sgx"))]
use thiserror_sgx as thiserror;

// error with std::error::Error implemented for std and sgx
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[cfg(any(feature = "std", feature = "sgx"))]
pub enum Error {
	#[error("No storage proof supplied")]
	NoProofSupplied,
	#[error("Supplied storage value does not match the value from the proof")]
	WrongValue,
	#[error("Invalid storage proof: StorageRootMismatch")]
	StorageRootMismatch,
	#[error("Storage value unavailable")]
	StorageValueUnavailable,
	#[error(transparent)]
	#[cfg(feature = "std")]
	Codec(#[from] codec::Error),

	// as `codec::Error` does not implement `std::error::Error` in `no-std`,
	// we can't use the `#[from]` attribute.
	#[error("Codec: {0}")]
	#[cfg(not(feature = "std"))]
	Codec(codec::Error),
}

// error for bare `no_std`, which does not implement `std::error::Error`

#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
use derive_more::{Display, From};

// Simple error enum for no_std without std::error::Error implemented
#[derive(Debug, Display, PartialEq, Eq, From)]
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
pub enum Error {
	NoProofSupplied,
	/// Supplied storage value does not match the value from the proof
	WrongValue,
	/// InvalidStorageProof,
	StorageRootMismatch,
	StorageValueUnavailable,
	Codec(codec::Error),
}
