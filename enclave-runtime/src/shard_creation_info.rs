/*
	Copyright 2021 Integritee AG
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
use crate::{
	error::{Error, Result as EnclaveResult},
	initialization::global_components::{EnclaveStf, GLOBAL_STATE_HANDLER_COMPONENT},
	shard_config,
	std::string::ToString,
	utils::DecodeRaw,
};
use codec::{Decode, Encode};
use itp_component_container::ComponentGetter;

use crate::utils::{
	get_validator_accessor_from_integritee_solo_or_parachain,
	get_validator_accessor_from_target_a_solo_or_parachain,
	get_validator_accessor_from_target_b_solo_or_parachain,
};
use itp_stf_interface::{
	parentchain_pallet::ParentchainPalletInstancesInterface, ShardCreationInfo, ShardCreationQuery,
};
use itp_stf_state_handler::{handle_state::HandleState, query_shard_state::QueryShardState};
use itp_types::{
	parentchain::{Hash, Header, IdentifyParentchain, ParentchainId},
	ShardIdentifier,
};
use itp_utils::{hex::hex_encode, write_slice_and_whitespace_pad};
use log::*;
use sgx_types::sgx_status_t;
use std::slice;

#[no_mangle]
pub unsafe extern "C" fn init_shard_creation_parentchain_header(
	shard: *const u8,
	shard_size: u32,
	parentchain_id: *const u8,
	parentchain_id_size: u32,
	header: *const u8,
	header_size: u32,
) -> sgx_status_t {
	let shard_identifier =
		ShardIdentifier::from_slice(slice::from_raw_parts(shard, shard_size as usize));
	let header = match Header::decode(&mut slice::from_raw_parts(header, header_size as usize)) {
		Ok(hdr) => hdr,
		Err(e) => {
			error!("Could not decode header: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};
	let parentchain_id =
		match ParentchainId::decode_raw(parentchain_id, parentchain_id_size as usize) {
			Ok(id) => id,
			Err(e) => {
				error!("Could not decode parentchain id: {:?}", e);
				return sgx_status_t::SGX_ERROR_UNEXPECTED
			},
		};

	if let Err(e) =
		init_shard_creation_parentchain_header_internal(shard_identifier, parentchain_id, header)
	{
		error!(
			"Failed to initialize first relevant parentchain header [{:?}]: {:?}",
			parentchain_id, e
		);
		return sgx_status_t::SGX_ERROR_UNEXPECTED
	}
	sgx_status_t::SGX_SUCCESS
}

fn init_shard_creation_parentchain_header_internal(
	shard: ShardIdentifier,
	parentchain_id: ParentchainId,
	header: Header,
) -> EnclaveResult<()> {
	if let Some(creation_block) =
		get_shard_creation_info_internal(shard)?.for_parentchain(parentchain_id)
	{
		error!("first relevant parentchain header has been previously initialized to {:?}. cannot change: {:?}", creation_block.number, parentchain_id);
		return Err(Error::Other(
			"first relevant parentchain header has been previously initialized. cannot change"
				.into(),
		))
	}
	debug!(
		"[{:?}] initializing shard creation header: number: {} hash: {}",
		parentchain_id,
		header.number,
		hex_encode(header.hash().encode().as_ref())
	);

	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
	if !state_handler
		.shard_exists(&shard)
		.map_err(|_| Error::Other("get shard_exists failed".into()))?
	{
		return Err(Error::Other("shard not initialized".into()))
	};

	let (state_lock, mut state) = state_handler.load_for_mutation(&shard)?;

	EnclaveStf::set_creation_block(&mut state, header, parentchain_id)
		.map_err(|e| Error::Stf(e.to_string()))?;

	let genesis_hash = get_genesis_hash(parentchain_id)?;
	EnclaveStf::set_genesis_hash(&mut state, genesis_hash, parentchain_id)
		.map_err(|e| Error::Stf(e.to_string()))?;

	state_handler.write_after_mutation(state, state_lock, &shard)?;

	shard_config::init_shard_config(shard)?;
	Ok(())
}

fn get_genesis_hash(parentchain_id: ParentchainId) -> EnclaveResult<Hash> {
	match parentchain_id {
		ParentchainId::Integritee =>
			get_validator_accessor_from_integritee_solo_or_parachain()?.genesis_hash(),
		ParentchainId::TargetA =>
			get_validator_accessor_from_target_a_solo_or_parachain()?.genesis_hash(),
		ParentchainId::TargetB =>
			get_validator_accessor_from_target_b_solo_or_parachain()?.genesis_hash(),
	}
	.ok_or_else(|| Error::Other("genesis hash missing for parentchain".into()))
}
/// reads the shard vault account id form state if it has been initialized previously
pub(crate) fn get_shard_creation_info_internal(
	shard: ShardIdentifier,
) -> EnclaveResult<ShardCreationInfo> {
	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
	let (_state_lock, mut state) = state_handler.load_for_mutation(&shard)?;
	Ok(EnclaveStf::get_shard_creation_info(&mut state))
}

/// reads the shard vault account id form state if it has been initialized previously
#[no_mangle]
pub unsafe extern "C" fn get_shard_creation_info(
	shard: *const u8,
	shard_size: u32,
	creation: *mut u8,
	creation_size: u32,
) -> sgx_status_t {
	let shard = ShardIdentifier::from_slice(slice::from_raw_parts(shard, shard_size as usize));

	let shard_creation_info = match get_shard_creation_info_internal(shard) {
		Ok(creation) => creation,
		Err(e) => {
			warn!("Failed to fetch creation header: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};
	trace!("fetched shard creation header from state: {:?}", shard_creation_info);

	let creation_slice = slice::from_raw_parts_mut(creation, creation_size as usize);
	if let Err(e) = write_slice_and_whitespace_pad(creation_slice, shard_creation_info.encode()) {
		return Error::BufferError(e).into()
	};
	sgx_status_t::SGX_SUCCESS
}
