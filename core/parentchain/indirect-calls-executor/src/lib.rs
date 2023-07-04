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
//! Execute indirect calls, i.e. extrinsics extracted from parentchain blocks.
//!
//! The core struct of this crate is the [IndirectCallsExecutor] executor. It scans parentchain
//! blocks for relevant extrinsics, derives an indirect call for those and dispatches the
//! indirect call.

#![feature(trait_alias)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, feature(assert_matches))]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use futures_sgx as futures;
	pub use thiserror_sgx as thiserror;
}

mod event_filter;
mod executor;
mod traits;

pub mod error;
pub mod filter_metadata;
pub mod indirect_calls;
pub mod parentchain_parser;

pub use error::{Error, Result};
pub use executor::IndirectCallsExecutor;
pub use traits::{ExecuteIndirectCalls, IndirectDispatch, IndirectExecutor};
