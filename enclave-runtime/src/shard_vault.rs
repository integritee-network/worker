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
	initialization::global_components::{
		GLOBAL_OCALL_API_COMPONENT, GLOBAL_SIGNING_KEY_REPOSITORY_COMPONENT,
		GLOBAL_STATE_HANDLER_COMPONENT,
	},
	utils::{
		get_extrinsic_factory_from_integritee_solo_or_parachain,
		get_node_metadata_repository_from_integritee_solo_or_parachain,
	},
};
use codec::{Compact, Decode, Encode};
use itp_component_container::ComponentGetter;
use itp_extrinsics_factory::CreateExtrinsics;
use itp_node_api::{
	api_client::{PairSignature, StaticExtrinsicSigner},
	metadata::{
		pallet_proxy::PROXY_DEPOSIT,
		provider::{AccessNodeMetadata, Error as MetadataProviderError},
	},
};
use itp_node_api_metadata::pallet_proxy::ProxyCallIndexes;
use itp_nonce_cache::NonceCache;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_sgx_crypto::key_repository::AccessKey;
use itp_stf_interface::SHARD_VAULT_KEY;
use itp_stf_state_handler::{handle_state::HandleState, query_shard_state::QueryShardState};
use itp_types::{
	parentchain::{AccountId, Address, ParentchainId, ProxyType},
	OpaqueCall, ShardIdentifier,
};
use log::*;
use sgx_types::sgx_status_t;
use sp_core::crypto::{DeriveJunction, Pair};
use std::{slice, sync::Arc, vec::Vec};

#[no_mangle]
pub unsafe extern "C" fn init_proxied_shard_vault(
	shard: *const u8,
	shard_size: u32,
) -> sgx_status_t {
	let shard_identifier =
		ShardIdentifier::from_slice(slice::from_raw_parts(shard, shard_size as usize));

	if let Err(e) = init_proxied_shard_vault_internal(shard_identifier) {
		error!("Failed to initialize proxied shard vault ({:?}): {:?}", shard_identifier, e);
		return sgx_status_t::SGX_ERROR_UNEXPECTED
	}

	sgx_status_t::SGX_SUCCESS
}

/// reads the shard vault account id form state if it has been initialized previously
#[no_mangle]
pub unsafe extern "C" fn get_ecc_vault_pubkey(
	shard: *const u8,
	shard_size: u32,
	pubkey: *mut u8,
	pubkey_size: u32,
) -> sgx_status_t {
	let shard = ShardIdentifier::from_slice(slice::from_raw_parts(shard, shard_size as usize));

	let shard_vault = match get_shard_vault_account(shard) {
		Ok(account) => account,
		Err(e) => {
			error!("Failed to fetch shard vault account: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);
	pubkey_slice.clone_from_slice(shard_vault.encode().as_slice());
	sgx_status_t::SGX_SUCCESS
}

/// reads the shard vault account id form state if it has been initialized previously
pub(crate) fn get_shard_vault_account(shard: ShardIdentifier) -> EnclaveResult<AccountId> {
	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;

	state_handler
		.execute_on_current(&shard, |state, _| {
			state
				.state
				.get::<Vec<u8>>(&SHARD_VAULT_KEY.into())
				.and_then(|v| Decode::decode(&mut v.clone().as_slice()).ok())
		})?
		.ok_or_else(|| {
			Error::Other("failed to fetch shard vault account. has it been initialized?".into())
		})
}

pub(crate) fn init_proxied_shard_vault_internal(shard: ShardIdentifier) -> EnclaveResult<()> {
	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
	if !state_handler.shard_exists(&shard).unwrap() {
		return Err(Error::Other("shard not initialized".into()))
	};

	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;
	let enclave_signer = GLOBAL_SIGNING_KEY_REPOSITORY_COMPONENT.get()?.retrieve_key()?;
	let enclave_extrinsics_factory = get_extrinsic_factory_from_integritee_solo_or_parachain()?;
	let node_metadata_repo = get_node_metadata_repository_from_integritee_solo_or_parachain()?;
	let vault = enclave_signer
		.derive(vec![DeriveJunction::hard(shard.encode())].into_iter(), None)
		.map_err(|_| Error::Other("failed to derive shard vault keypair".into()))?
		.0;

	info!("shard vault account derived pubkey: 0x{}", hex::encode(vault.public().0));

	let (state_lock, mut state) = state_handler.load_for_mutation(&shard)?;
	state.state.insert(SHARD_VAULT_KEY.into(), vault.public().0.to_vec());
	state_handler.write_after_mutation(state, state_lock, &shard)?;

	info!("send existential funds from enclave account to vault account");
	let call_ids = node_metadata_repo
		.get_from_metadata(|m| m.call_indexes("Balances", "transfer_keep_alive"))?
		.map_err(MetadataProviderError::MetadataError)?;

	let call = OpaqueCall::from_tuple(&(
		call_ids,
		Address::from(AccountId::from(vault.public().0)),
		Compact(PROXY_DEPOSIT),
	));

	info!("vault funding call: 0x{}", hex::encode(call.0.clone()));
	let xts = enclave_extrinsics_factory.create_extrinsics(&[call], None)?;

	//this extrinsic must be included in a block before we can move on. otherwise the next will fail
	ocall_api.send_to_parentchain(xts, &ParentchainId::Integritee, true)?;

	// we are assuming nonce=0 here.
	let nonce_cache = Arc::new(NonceCache::default());
	let vault_extrinsics_factory = enclave_extrinsics_factory
		.with_signer(StaticExtrinsicSigner::<_, PairSignature>::new(vault), nonce_cache);

	info!("register enclave signer as proxy for shard vault");
	let call_ids = node_metadata_repo
		.get_from_metadata(|m| m.call_indexes("Proxy", "add_proxy"))?
		.map_err(MetadataProviderError::MetadataError)?;

	let call = OpaqueCall::from_tuple(&(
		call_ids,
		Address::from(AccountId::from(enclave_signer.public().0)),
		ProxyType::Any,
		0u32, // delay
	));

	info!("add proxy call: 0x{}", hex::encode(call.0.clone()));
	let xts = vault_extrinsics_factory.create_extrinsics(&[call], None)?;

	ocall_api.send_to_parentchain(xts, &ParentchainId::Integritee, false)?;
	Ok(())
}

pub(crate) fn add_shard_vault_proxy(
	shard: ShardIdentifier,
	proxy: &AccountId,
) -> EnclaveResult<()> {
	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
	if !state_handler.shard_exists(&shard).unwrap() {
		return Err(Error::Other("shard not initialized".into()))
	};

	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;
	let enclave_extrinsics_factory = get_extrinsic_factory_from_integritee_solo_or_parachain()?;
	let node_metadata_repo = get_node_metadata_repository_from_integritee_solo_or_parachain()?;
	let vault = get_shard_vault_account(shard)?;

	debug!(
		"adding proxy 0x{} to shard vault account 0x{}",
		hex::encode(proxy.clone()),
		hex::encode(vault.clone())
	);

	let add_proxy_call = OpaqueCall::from_tuple(&(
		node_metadata_repo.get_from_metadata(|m| m.add_proxy_call_indexes())??,
		Address::from(proxy.clone()),
		ProxyType::Any,
		0u32, // delay
	));
	let call = OpaqueCall::from_tuple(&(
		node_metadata_repo.get_from_metadata(|m| m.proxy_call_indexes())??,
		Address::from(vault),
		None::<ProxyType>,
		add_proxy_call,
	));

	info!("proxied add proxy call: 0x{}", hex::encode(call.0.clone()));
	let xts = enclave_extrinsics_factory.create_extrinsics(&[call], None)?;

	ocall_api.send_to_parentchain(xts, &ParentchainId::Integritee, false)?;
	Ok(())
}
