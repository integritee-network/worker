//! All the different crypto schemes that we use in sgx

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

#[cfg(feature = "sgx")]
pub mod aes;
pub mod error;
pub mod traits;

#[cfg(feature = "sgx")]
pub use self::aes::*;
pub use error::*;
pub use traits::*;
