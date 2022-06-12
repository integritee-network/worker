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

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;
// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use thiserror_sgx as thiserror;
}

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;


/// Basic storage access abstraction

use codec::Decode;
use core::result::Result as StdResult;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_storage::{verify_storage_entries, Error as StorageError, StorageEntryVerified};
use itp_types::WorkerRequest;
use sp_core::H256;
use sp_runtime::traits::Header;
use sp_std::{prelude::*, vec};
use std::format;

/// Very basic abstraction over storage access that returns a `StorageEntryVerified`. This enforces
/// that the implementation of this trait uses the `itp_storage::VerifyStorageProof` trait
/// because a `StorageEntryVerified` instance cannot be created otherwise.
///
/// This is very generic and most-likely one of the innermost traits.
pub trait GetStorageVerified {
	fn get_storage_verified<H: Header<Hash = H256>, V: Decode>(
		&self,
		storage_hash: Vec<u8>,
		header: &H,
	) -> Result<StorageEntryVerified<V>>;

	fn get_multiple_storages_verified<H: Header<Hash = H256>, V: Decode>(
		&self,
		storage_hashes: Vec<Vec<u8>>,
		header: &H,
	) -> Result<Vec<StorageEntryVerified<V>>>;
}

impl<O: EnclaveOnChainOCallApi> GetStorageVerified for O {
	fn get_storage_verified<H: Header<Hash = H256>, V: Decode>(
		&self,
		storage_hash: Vec<u8>,
		header: &H,
	) -> Result<StorageEntryVerified<V>> {
		// the code below seems like an overkill, but it is surprisingly difficult to
		// get an owned value from a `Vec` without cloning.
		Ok(self
			.get_multiple_storages_verified(vec![storage_hash], header)?
			.into_iter()
			.next()
			.ok_or(StorageError::StorageValueUnavailable)?)
	}

	fn get_multiple_storages_verified<H: Header<Hash = H256>, V: Decode>(
		&self,
		storage_hashes: Vec<Vec<u8>>,
		header: &H,
	) -> Result<Vec<StorageEntryVerified<V>>> {
		let requests = storage_hashes
			.into_iter()
			.map(|key| WorkerRequest::ChainStorage(key, Some(header.hash())))
			.collect();

		let storage_entries = self
			.worker_request::<Vec<u8>>(requests)
			.map(|storages| verify_storage_entries(storages, header))??;

		Ok(storage_entries)
	}
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("Storage error: {0}")]
	Storage(#[from] StorageError),
	#[error("SGX error, status: {0}")]
	Sgx(sgx_types::sgx_status_t),
	#[error("Error, other: {0}")]
	Other(#[from] Box<dyn std::error::Error + Sync + Send + 'static>),
}

impl From<sgx_types::sgx_status_t> for Error {
	fn from(sgx_status: sgx_types::sgx_status_t) -> Self {
		Self::Sgx(sgx_status)
	}
}

impl From<codec::Error> for Error {
	fn from(e: codec::Error) -> Self {
		Self::Other(format!("{:?}", e).into())
	}
}

pub type Result<T> = StdResult<T, Error>;
