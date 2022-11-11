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

use crate::light_client::light_client_init_params::{GrandpaParams, SimpleParams};
use codec::{Decode, Encode};

use sp_runtime::traits::Block;

pub use itp_types::{Block as ParachainBlock, Block as SolochainBlock};
pub type HeaderFor<B> = <B as Block>::Header;
pub type SolochainHeader = HeaderFor<SolochainBlock>;
pub type ParachainHeader = HeaderFor<ParachainBlock>;
pub type SolochainParams = GrandpaParams<SolochainHeader>;
pub type ParachainParams = SimpleParams<ParachainHeader>;

/// Initialization primitives, used by both service and enclave.
/// Allows to use a single E-call for the initialization of different parentchain types.
#[derive(Encode, Decode, Clone)]
pub enum ParentchainInitParams {
	Solochain { params: SolochainParams },
	Parachain { params: ParachainParams },
}

impl From<SolochainParams> for ParentchainInitParams {
	fn from(params: SolochainParams) -> Self {
		ParentchainInitParams::Solochain { params }
	}
}

impl From<ParachainParams> for ParentchainInitParams {
	fn from(params: ParachainParams) -> Self {
		ParentchainInitParams::Parachain { params }
	}
}
