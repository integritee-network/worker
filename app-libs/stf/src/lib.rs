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

/////////////////////////////////////////////////////////////////////////////
#![feature(structural_match)]
#![feature(rustc_attrs)]
#![feature(core_intrinsics)]
#![feature(arbitrary_enum_discriminant)]
#![feature(derive_eq)]
#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate alloc;
#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

pub use getter::*;
pub use stf_sgx_primitives::{types::*, Stf};
pub use trusted_call::*;

#[cfg(feature = "evm")]
pub mod evm_helpers;
pub mod getter;
pub mod guess_the_number;
pub mod hash;
pub mod helpers;
pub mod parentchain_mirror;
pub mod stf_sgx;
pub mod stf_sgx_primitives;
#[cfg(all(feature = "test", feature = "sgx"))]
pub mod stf_sgx_tests;
#[cfg(all(feature = "test", feature = "sgx"))]
pub mod test_genesis;
pub mod trusted_call;

pub(crate) const ENCLAVE_ACCOUNT_KEY: &str = "Enclave_Account_Key";
pub const STF_SHIELDING_FEE_AMOUNT_DIVIDER: Balance = 571; // approx 0.175%
pub const STF_TX_FEE_UNIT_DIVIDER: Balance = 100; // 0.01 tokens
pub const STF_BYTE_FEE_UNIT_DIVIDER: Balance = 10_000; // 0.0001 tokens per byte of certain payload

pub const STF_GUESS_FEE_UNIT_DIVIDER: Balance = 10; // 0.1 tokens

pub const STF_SESSION_PROXY_DEPOSIT_DIVIDER: Balance = 10; // 0.1 tokens
