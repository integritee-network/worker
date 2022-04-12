//! All the different crypto schemes that we use in sgx

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use serde_json_sgx as serde_json;
	pub use serde_sgx as serde;
}

pub mod aes;
pub mod ed25519;
pub mod error;
pub mod traits;

#[cfg(feature = "sgx")]
pub mod rsa3072;

#[cfg(feature = "sgx")]
pub use self::aes::*;
#[cfg(feature = "sgx")]
pub use self::ed25519::*;
#[cfg(feature = "sgx")]
pub use self::rsa3072::*;
pub use error::*;
pub use traits::*;

#[cfg(feature = "mocks")]
pub mod mocks;
