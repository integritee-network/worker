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

pub use itp_types::{parentchain::ParentchainId, Block as ParachainBlock, Block as SolochainBlock};
pub type HeaderFor<B> = <B as Block>::Header;
pub type SolochainHeader = HeaderFor<SolochainBlock>;
pub type ParachainHeader = HeaderFor<ParachainBlock>;
pub type SolochainParams = GrandpaParams<SolochainHeader>;
pub type ParachainParams = SimpleParams<ParachainHeader>;

/// Initialization primitives, used by both service and enclave.
/// Allows to use a single E-call for the initialization of different parentchain types.
#[derive(Encode, Decode, Clone)]
pub enum ParentchainInitParams {
	Solochain { id: ParentchainId, params: SolochainParams },
	Parachain { id: ParentchainId, params: ParachainParams },
}

impl ParentchainInitParams {
	pub fn id(&self) -> &ParentchainId {
		match self {
			Self::Solochain { id, .. } => id,
			Self::Parachain { id, .. } => id,
		}
	}
}

impl From<(ParentchainId, SolochainParams)> for ParentchainInitParams {
	fn from(value: (ParentchainId, SolochainParams)) -> Self {
		Self::Solochain { id: value.0, params: value.1 }
	}
}

impl From<(ParentchainId, ParachainParams)> for ParentchainInitParams {
	fn from(value: (ParentchainId, ParachainParams)) -> Self {
		Self::Parachain { id: value.0, params: value.1 }
	}
}
