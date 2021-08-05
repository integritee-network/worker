#![cfg_attr(not(feature = "std"), no_std)]

//! Test-utils crate which contains mocks and soon some fixtures.

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

pub mod mock;
