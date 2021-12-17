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

//! stores all primitives of the enclave that do need to be accessed frequently, but should
//! not be frequently mutated, such as keys and server urls.
//!
//! TODO: For now only the mu-ra server url is stored here. Keys and such could also be stored here.

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(assert_matches)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

// Re-export module to properly feature gate sgx and regular std environment.
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use thiserror_sgx as thiserror;
}

#[cfg(feature = "std")]
use std::sync::RwLockWriteGuard;
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use std::sync::SgxRwLockWriteGuard as RwLockWriteGuard;

use crate::error::Result;
use lazy_static::lazy_static;
use std::{
	string::{String, ToString},
	sync::Arc,
};

pub use primitives_cache::PrimitivesCache;

lazy_static! {
	/// Global instance of the primitves cache.
	///
	/// Concurrent access is managed internally, using RW locks.
	pub static ref GLOBAL_PRIMITIVES_CACHE: Arc<PrimitivesCache> = Default::default();
}

pub mod error;
pub mod primitives_cache;

#[derive(Default, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Primitives {
	mu_ra_url: String,
}

impl Primitives {
	pub fn new(mu_ra_url: &str) -> Primitives {
		Primitives { mu_ra_url: mu_ra_url.to_string() }
	}

	pub fn mu_ra_url(&self) -> &str {
		&self.mu_ra_url
	}
}

/// Trait to mutate the primitives.
///
/// Used in a combination of loading a lock and then writing the updated
/// value back, returning the lock again.
pub trait MutatePrimitives {
	fn load_for_mutation(&self) -> Result<RwLockWriteGuard<'_, Primitives>>;
}

/// Trait to get the primitives.
pub trait GetPrimitives {
	/// Returns a clone of the full Primitives struct.
	fn get_primitives(&self) -> Result<Primitives>;

	fn get_mu_ra_url(&self) -> Result<String>;
}
