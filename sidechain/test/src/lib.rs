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

#![feature(trait_alias)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be disabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

pub mod sidechain_block_builder;
pub mod sidechain_block_data_builder;
pub mod sidechain_header_builder;
