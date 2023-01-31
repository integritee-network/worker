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
#[macro_use]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use base64_sgx as base64;
	pub use chrono_sgx as chrono;
	pub use rustls_sgx as rustls;
	pub use serde_json_sgx as serde_json;
	pub use thiserror_sgx as thiserror;
	pub use webpki_sgx as webpki;
	pub use yasna_sgx as yasna;
}

#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod attestation_handler;

pub mod collateral;

pub mod cert;

pub mod error;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub use attestation_handler::{AttestationHandler, IntelAttestationHandler, DEV_HOSTNAME};
pub use collateral::SgxQlQveCollateral;

pub use error::{Error, Result};
