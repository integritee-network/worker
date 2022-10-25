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

extern crate alloc;

use crate::light_client::light_client_init_params::{GrandpaParams, ParachainParams};
use alloc::vec::Vec;
use codec::{Decode, Encode};

/// Initialization primitives, used to by both service and enclave.
/// Allows to use one E-call for the initialization of different parentchain types.
#[derive(Encode, Decode, Clone)]
pub enum ParentchainInitParams {
	Grandpa { encoded_params: Vec<u8> },
	Parachain { encoded_params: Vec<u8> },
}

impl<Header: Encode> From<GrandpaParams<Header>> for ParentchainInitParams {
	fn from(item: GrandpaParams<Header>) -> Self {
		ParentchainInitParams::Grandpa { encoded_params: item.encode() }
	}
}

impl<Header: Encode> From<ParachainParams<Header>> for ParentchainInitParams {
	fn from(item: ParachainParams<Header>) -> Self {
		ParentchainInitParams::Parachain { encoded_params: item.encode() }
	}
}
