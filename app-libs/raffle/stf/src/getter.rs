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

use crate::RaffleIndex;
use codec::{Decode, Encode};
use ita_sgx_runtime::Runtime;
use itp_stf_interface::ExecuteGetter;
use itp_stf_primitives::types::AccountId;
use sp_std::vec::Vec;

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum RafflePublicGetter {
	all_ongoing_raffles,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum RaffleTrustedGetter {
	merkle_proof { origin: AccountId, raffle_index: RaffleIndex },
}

impl RaffleTrustedGetter {
	pub fn sender_account(&self) -> &AccountId {
		match self {
			Self::merkle_proof { origin, .. } => origin,
		}
	}
}

impl ExecuteGetter for RaffleTrustedGetter {
	fn execute(self) -> Option<Vec<u8>> {
		match self {
			Self::merkle_proof { origin, raffle_index } =>
				pallet_raffles::Pallet::<Runtime>::merkle_proof_for_registration(
					raffle_index,
					&origin,
				)
				.map(|proof| proof.encode()),
		}
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		Vec::new()
	}
}

impl ExecuteGetter for RafflePublicGetter {
	fn execute(self) -> Option<Vec<u8>> {
		match self {
			Self::all_ongoing_raffles =>
				Some(pallet_raffles::Pallet::<Runtime>::all_ongoing_raffles().encode()),
		}
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		Vec::new()
	}
}
