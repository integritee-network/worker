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

// #[cfg(all(not(feature = "std"), feature = "sgx"))]
// use crate::sgx_reexport_prelude::*;

use crate::{
	error::{Error, Result},
	traits::{StatePostProcessing, StfExecuteShieldFunds, StfExecuteTrustedCall, StfUpdateState},
};
use codec::{Decode, Encode};
use ita_stf::{
	stf_sgx::{shards_key_hash, storage_hashes_to_update_per_shard},
	AccountId, ShardIdentifier, StateTypeDiff, Stf, TrustedCall, TrustedCallSigned,
};
use itp_ocall_api::{EnclaveAttestationOCallApi, EnclaveOnChainOCallApi};
use itp_stf_state_handler::handle_state::HandleState;
use itp_storage::StorageEntryVerified;
use itp_storage_verifier::GetStorageVerified;
use itp_types::{Amount, OpaqueCall, H256};
use log::*;
use sgx_externalities::SgxExternalitiesTrait;
use sp_runtime::{
	app_crypto::sp_core::blake2_256,
	traits::{Block as BlockT, Header, UniqueSaturatedInto},
};
use std::{collections::HashMap, sync::Arc, vec::Vec};

/// STF Executor implementation
///
///
pub struct StfExecutor<OCallApi, StateHandler> {
	ocall_api: Arc<OCallApi>,
	state_handler: StateHandler,
}

impl<OCallApi, StateHandler> StfExecutor<OCallApi, StateHandler>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi + GetStorageVerified,
	StateHandler: HandleState,
{
	pub fn new(ocall_api: Arc<OCallApi>, state_handler: StateHandler) -> Self {
		StfExecutor { ocall_api, state_handler }
	}
}

impl<OCallApi, StateHandler> StfExecuteTrustedCall for StfExecutor<OCallApi, StateHandler>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi + GetStorageVerified,
	StateHandler: HandleState,
{
	fn execute_trusted_call<PB>(
		&self,
		calls: &mut Vec<OpaqueCall>,
		stf_call_signed: &TrustedCallSigned,
		header: &PB::Header,
		shard: ShardIdentifier,
		post_processing: StatePostProcessing,
	) -> Result<Option<(H256, H256)>>
	where
		PB: BlockT<Hash = H256>,
	{
		// load state before executing any calls
		let (state_lock, mut state) = self.state_handler.load_for_mutation(&shard)?;

		debug!("query mrenclave of self");
		let mrenclave = self.ocall_api.get_mrenclave_of_self()?;
		//debug!("MRENCLAVE of self is {}", mrenclave.m.to_base58());

		if let false = stf_call_signed.verify_signature(&mrenclave.m, &shard) {
			error!("TrustedCallSigned: bad signature");
			// do not panic here or users will be able to shoot workers dead by supplying a bad signature
			return Ok(None)
		}

		// Necessary because light client sync may not be up to date
		// see issue #208
		debug!("Update STF storage!");
		let storage_hashes = Stf::get_storage_hashes_to_update(&stf_call_signed);
		let update_map = self
			.ocall_api
			.get_multiple_storages_verified(storage_hashes, header)
			.map(into_map)?;
		Stf::update_storage(&mut state, &update_map.into());

		debug!("execute STF");
		if let Err(e) = Stf::execute(&mut state, stf_call_signed.clone(), calls) {
			error!("Error performing Stf::execute. Error: {:?}", e);
			return Ok(None)
		}

		let call_hash = blake2_256(&stf_call_signed.encode());
		let operation = stf_call_signed.clone().into_trusted_operation(true);
		let operation_hash = blake2_256(&operation.encode());
		debug!("Operation hash {:?}", operation_hash);
		debug!("Call hash {:?}", call_hash);

		if let StatePostProcessing::Prune = post_processing {
			state.prune_state_diff();
		}

		trace!("Updating state of shard {:?}", shard);
		self.state_handler.write(state, state_lock, &shard)?;

		Ok(Some((H256::from(call_hash), H256::from(operation_hash))))
	}
}

impl<OCallApi, StateHandler> StfExecuteShieldFunds for StfExecutor<OCallApi, StateHandler>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi + GetStorageVerified,
	StateHandler: HandleState,
{
	fn execute_shield_funds(
		&self,
		account: AccountId,
		amount: Amount,
		shard: &ShardIdentifier,
		calls: &mut Vec<OpaqueCall>,
	) -> Result<H256> {
		let (state_lock, mut state) = self.state_handler.load_for_mutation(&shard)?;

		let root = Stf::get_root(&mut state);
		let nonce = Stf::account_nonce(&mut state, &root);

		let trusted_call = TrustedCallSigned::new(
			TrustedCall::balance_shield(root, account, amount),
			nonce,
			Default::default(), //don't care about signature here
		);

		Stf::execute(&mut state, trusted_call, calls).map_err::<Error, _>(|e| e.into())?;

		self.state_handler.write(state, state_lock, &shard).map_err(|e| e.into())
	}
}

impl<OCallApi, StateHandler> StfUpdateState for StfExecutor<OCallApi, StateHandler>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi + GetStorageVerified,
	StateHandler: HandleState,
{
	fn update_states<PB>(&self, header: &PB::Header) -> Result<()>
	where
		PB: BlockT<Hash = H256>,
	{
		debug!("Update STF storage upon block import!");
		let storage_hashes = Stf::storage_hashes_to_update_on_block();

		if storage_hashes.is_empty() {
			return Ok(())
		}

		// global requests they are the same for every shard
		let state_diff_update: StateTypeDiff = self
			.ocall_api
			.get_multiple_storages_verified(storage_hashes, header)
			.map(into_map)?
			.into();

		// look for new shards an initialize them
		if let Some(maybe_shards) = state_diff_update.get(&shards_key_hash()) {
			match maybe_shards {
				Some(shards) => {
					let shards: Vec<ShardIdentifier> = Decode::decode(&mut shards.as_slice())?;

					for shard_id in shards {
						let (state_lock, mut state) =
							self.state_handler.load_for_mutation(&shard_id)?;
						trace!("Successfully loaded state, updating states ...");

						// per shard (cid) requests
						let per_shard_hashes = storage_hashes_to_update_per_shard(&shard_id);
						let per_shard_update = self
							.ocall_api
							.get_multiple_storages_verified(per_shard_hashes, header)
							.map(into_map)?;

						Stf::update_storage(&mut state, &per_shard_update.into());
						Stf::update_storage(&mut state, &state_diff_update);

						// block number is purged from the substrate state so it can't be read like other storage values
						// The number conversion is a bit unfortunate, but I wanted to prevent making the stf generic for now
						Stf::update_layer_one_block_number(
							&mut state,
							(*header.number()).unique_saturated_into(),
						);

						self.state_handler.write(state, state_lock, &shard_id)?;
					}
				},
				None => debug!("No shards are on the chain yet"),
			};
		};
		Ok(())
	}
}

fn into_map(
	storage_entries: Vec<StorageEntryVerified<Vec<u8>>>,
) -> HashMap<Vec<u8>, Option<Vec<u8>>> {
	storage_entries.into_iter().map(|e| e.into_tuple()).collect()
}
