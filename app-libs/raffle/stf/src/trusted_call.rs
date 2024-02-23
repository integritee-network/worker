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

use codec::{Compact, Decode, Encode};
use frame_support::{ensure, traits::UnfilteredDispatchable};
pub use ita_sgx_runtime::{Balance, Index};
use ita_sgx_runtime::{
	ParentchainInstanceIntegritee, ParentchainInstanceTargetA, ParentchainInstanceTargetB,
	ParentchainIntegritee, Runtime, System,
};
use itp_node_api::metadata::{provider::AccessNodeMetadata, NodeMetadataTrait};
use itp_node_api_metadata::{
	pallet_balances::BalancesCallIndexes, pallet_enclave_bridge::EnclaveBridgeCallIndexes,
	pallet_proxy::ProxyCallIndexes,
};
use itp_stf_interface::ExecuteCall;
use itp_stf_primitives::{
	error::StfError,
	traits::{TrustedCallSigning, TrustedCallVerification},
	types::{AccountId, KeyPair, ShardIdentifier, Signature, TrustedOperation},
};
use itp_types::{
	parentchain::{ParentchainCall, ParentchainId, ProxyType},
	Address, Moment, OpaqueCall,
};
use itp_utils::stringify::account_id_to_string;
use log::*;
use sp_core::{
	crypto::{AccountId32, UncheckedFrom},
	ed25519,
};
use sp_io::hashing::blake2_256;
use sp_runtime::{traits::Verify, MultiAddress, MultiSignature};
use std::{format, prelude::v1::*, sync::Arc};

pub use pallet_raffles::{RaffleCount, RaffleIndex, WinnerCount};

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum RaffleTrustedCall {
	addRaffle { origin: AccountId, winner_count: WinnerCount },
	registerForRaffle { origin: AccountId, raffle_index: RaffleIndex },
	drawWinners { origin: AccountId, raffle_index: RaffleIndex },
}

impl RaffleTrustedCall {
	pub fn sender_account(&self) -> &AccountId {
		match self {
			Self::addRaffle { origin, .. } => origin,
			Self::drawWinners { origin, .. } => origin,
			Self::registerForRaffle { origin, .. } => origin,
		}
	}
}

impl<NodeMetadataRepository> ExecuteCall<NodeMetadataRepository> for RaffleTrustedCall
where
	NodeMetadataRepository: AccessNodeMetadata,
	NodeMetadataRepository::MetadataType: NodeMetadataTrait,
{
	type Error = StfError;

	fn execute(
		self,
		calls: &mut Vec<ParentchainCall>,
		node_metadata_repo: Arc<NodeMetadataRepository>,
	) -> Result<(), Self::Error> {
		match self {
			Self::addRaffle { origin, winner_count } => {
				debug!("createRaffle called by {}", account_id_to_string(&origin),);
				let origin = ita_sgx_runtime::RuntimeOrigin::signed(origin.clone());

				pallet_raffles::Call::<Runtime>::add_raffle { winner_count }
					.dispatch_bypass_filter(origin.clone())
					.map_err(|e| {
						Self::Error::Dispatch(format!("Create Raffle error: {:?}", e.error))
					})?;

				Runtime::read_events().last().map(|event| -> Result<(), Self::Error> {
					calls.push(ParentchainCall::Integritee(OpaqueCall::from_tuple(&(
						node_metadata_repo
							.get_from_metadata(|m| m.publish_hash_call_indexes())
							.map_err(|_| Self::Error::InvalidMetadata)?
							.map_err(|_| Self::Error::InvalidMetadata)?,
						itp_types::H256::default(), // don't bother with the call hash for now.
						Vec::<itp_types::H256>::new(),
						format!("{:?}", event),
					))));
					Ok(())
				});

				Ok::<(), Self::Error>(())
			},
			Self::registerForRaffle { origin, raffle_index } => {
				debug!("registerForRaffle {}", account_id_to_string(&origin),);
				Ok::<(), Self::Error>(())
			},
			Self::drawWinners { origin, raffle_index } => {
				debug!("drawWinners called by {}", account_id_to_string(&origin),);
				Ok::<(), Self::Error>(())
			},
		}
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		let key_hashes = Vec::new();
		match self {
			_ => debug!("No storage updates needed..."),
		};
		key_hashes
	}
}
