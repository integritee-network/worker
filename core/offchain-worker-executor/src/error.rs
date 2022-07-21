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

use std::boxed::Box;

pub type Result<T> = core::result::Result<T, Error>;

/// General offchain-worker error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("STF state handler error: {0}")]
	StfStateHandler(#[from] itp_stf_state_handler::error::Error),
	#[error("STF executor error: {0}")]
	StfExecutor(#[from] itp_stf_executor::error::Error),
	#[error("TOP pool author error: {0}")]
	TopPoolAuthor(#[from] itp_top_pool_author::error::Error),
	#[error("Light-client error: {0}")]
	LightClient(#[from] itc_parentchain_light_client::error::Error),
	#[error("Extrinsics factory error: {0}")]
	ExtrinsicsFactory(#[from] itp_extrinsics_factory::error::Error),
	#[error("{0}")]
	Other(Box<dyn std::error::Error + Sync + Send + 'static>),
}
