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

use derive_more::{Display, From};
use sgx_types::sgx_status_t;
use std::prelude::v1::Box;

#[derive(Debug, Display, From)]
pub enum Error {
	IO(std::io::Error),
	InvalidNonceKeyLength,
	Codec(codec::Error),
	Serialization(serde_json::Error),
	LockPoisoning,
	Other(Box<dyn std::error::Error + Sync + Send + 'static>),
}

pub type Result<T> = core::result::Result<T, Error>;

impl From<Error> for sgx_status_t {
	/// return sgx_status for top level enclave functions
	fn from(error: Error) -> sgx_status_t {
		log::warn!("Transform non-sgx-error into `SGX_ERROR_UNEXPECTED`: {:?}", error);
		sgx_status_t::SGX_ERROR_UNEXPECTED
	}
}
