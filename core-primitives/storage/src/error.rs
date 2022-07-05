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
use thiserror_sgx as thiserror;

use std::boxed::Box;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
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

	#[error(transparent)]
	Other(#[from] Box<dyn std::error::Error + Sync + Send + 'static>),
}

// error for bare `no_std`, which does not implement `std::error::Error`

#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
use derive_more::From;

// Simple error enum for no_std without std::error::Error implemented
#[derive(Debug, Debug, PartialEq, Eq From)]
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
