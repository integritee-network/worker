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

#[cfg(feature = "std")]
use rust_base58::base58::FromBase58Error;

#[cfg(feature = "sgx")]
use base58::FromBase58Error;

use crate::state_snapshot_primitives::StateId;
use itp_types::ShardIdentifier;
use sgx_types::sgx_status_t;
use std::{boxed::Box, format, string::String};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("Empty state repository")]
	EmptyRepository,
	#[error("State ID is invalid and does not exist: {0}")]
	InvalidStateId(StateId),
	#[error("Shard is invalid and does not exist: {0}")]
	InvalidShard(ShardIdentifier),
	#[error("State with hash {0} could not be found in the state repository")]
	StateNotFoundInRepository(String),
	#[error("State observer error: {0}")]
	StateObserver(#[from] itp_stf_state_observer::error::Error),
	#[error("Cache size for registry is zero")]
	ZeroCacheSize,
	#[error("Could not acquire lock, lock is poisoned")]
	LockPoisoning,
	#[error("OsString conversion error")]
	OsStringConversion,
	#[error("SGX crypto error: {0}")]
	CryptoError(itp_sgx_crypto::Error),
	#[error("IO error: {0}")]
	IO(std::io::Error),
	#[error("SGX error, status: {0}")]
	SgxError(sgx_status_t),
	#[error(transparent)]
	Other(#[from] Box<dyn std::error::Error + Sync + Send + 'static>),
}

impl From<std::io::Error> for Error {
	fn from(e: std::io::Error) -> Self {
		Self::IO(e)
	}
}

impl From<codec::Error> for Error {
	fn from(e: codec::Error) -> Self {
		Self::Other(format!("{:?}", e).into())
	}
}

impl From<sgx_status_t> for Error {
	fn from(sgx_status: sgx_status_t) -> Self {
		Self::SgxError(sgx_status)
	}
}

impl From<itp_sgx_crypto::Error> for Error {
	fn from(crypto_error: itp_sgx_crypto::Error) -> Self {
		Self::CryptoError(crypto_error)
	}
}

impl From<FromBase58Error> for Error {
	fn from(e: FromBase58Error) -> Self {
		Self::Other(format!("{:?}", e).into())
	}
}
