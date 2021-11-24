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

//! Reexport all the parentchain components in one crate

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

pub use itc_parentchain_block_import_dispatcher as block_import_dispatcher;

pub use itc_parentchain_block_import_queue as block_import_queue;

pub use itc_parentchain_block_importer as block_importer;

pub use itc_parentchain_indirect_calls_executor as indirect_calls_executor;

pub use itc_parentchain_light_client as light_client;
