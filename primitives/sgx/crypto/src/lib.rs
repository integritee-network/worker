#![cfg_attr(not(feature = "std"), no_std)]

//! All the different crypto types that are used in sgx

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

#[cfg(feature = "sgx")]
pub mod aes;
pub mod error;
pub mod traits;
