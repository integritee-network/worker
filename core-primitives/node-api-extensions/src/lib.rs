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

//! Some substrate-api-client extension traits.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, feature(assert_matches))]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use thiserror_sgx as thiserror;
}

#[cfg(all(not(feature = "sgx"), feature = "std"))]
pub use substrate_api_client::{rpc::WsRpcClient, Api, ApiClientError};

#[cfg(all(not(feature = "sgx"), feature = "std"))]
pub mod account;

#[cfg(all(not(feature = "sgx"), feature = "std"))]
pub mod chain;

#[cfg(all(not(feature = "sgx"), feature = "std"))]
pub mod node_api_factory;

#[cfg(all(not(feature = "sgx"), feature = "std"))]
pub mod pallet_teerex;

#[cfg(all(feature = "mocks", feature = "std"))]
pub mod pallet_teerex_api_mock;

pub mod error;
pub mod node_metadata_provider;

#[cfg(all(not(feature = "sgx"), feature = "std"))]
pub use account::*;
#[cfg(all(not(feature = "sgx"), feature = "std"))]
pub use chain::*;
#[cfg(all(not(feature = "sgx"), feature = "std"))]
pub use pallet_teerex::*;

#[cfg(all(not(feature = "sgx"), feature = "std"))]
use itp_types::ParentchainExtrinsicParams;

#[cfg(all(not(feature = "sgx"), feature = "std"))]
use sp_core::sr25519;

#[cfg(all(not(feature = "sgx"), feature = "std"))]
pub type ApiResult<T> = Result<T, ApiClientError>;

#[cfg(all(not(feature = "sgx"), feature = "std"))]
pub type ParentchainApi = Api<sr25519::Pair, WsRpcClient, ParentchainExtrinsicParams>;
