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
		EnclaveExtrinsicsFactory, EnclaveNodeMetadataRepository, EnclaveStf,
		GLOBAL_OCALL_API_COMPONENT, GLOBAL_SIGNING_KEY_REPOSITORY_COMPONENT,
		GLOBAL_STATE_HANDLER_COMPONENT,
	},
	std::string::ToString,
	utils::{
		get_extrinsic_factory_from_integritee_solo_or_parachain,
		get_extrinsic_factory_from_target_a_solo_or_parachain,
		get_extrinsic_factory_from_target_b_solo_or_parachain,
		get_node_metadata_repository_from_integritee_solo_or_parachain,
		get_node_metadata_repository_from_target_a_solo_or_parachain,
		get_node_metadata_repository_from_target_b_solo_or_parachain, try_mortality, DecodeRaw,
	},
};
use codec::{Compact, Decode, Encode};
use core::fmt::Debug;
use itp_component_container::ComponentGetter;
use itp_extrinsics_factory::CreateExtrinsics;
use itp_node_api::{
	api_client::{Config, PairSignature, StaticExtrinsicSigner},
	metadata::provider::{AccessNodeMetadata, Error as MetadataProviderError},
};
use itp_node_api_metadata::pallet_proxy::ProxyCallIndexes;
use itp_nonce_cache::NonceCache;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_sgx_crypto::key_repository::AccessKey;
use itp_stf_interface::{parentchain_pallet::ParentchainPalletInstancesInterface, ShardVaultQuery};
use itp_stf_state_handler::{handle_state::HandleState, query_shard_state::QueryShardState};
use itp_types::{
	parentchain::{AccountId, Address, Balance, Header, ParentchainId, ProxyType},
	Nonce, OpaqueCall, ShardIdentifier, WorkerRequest, WorkerResponse,
};
use log::*;
use primitive_types::H256;
use sgx_types::sgx_status_t;
use sp_core::crypto::{DeriveJunction, Pair};
use std::{slice, sync::Arc};

#[no_mangle]
pub unsafe extern "C" fn init_proxied_shard_vault(
	shard: *const u8,
	shard_size: u32,
	parentchain_id: *const u8,
	parentchain_id_size: u32,
	funding_balance: *const u8,
	funding_balance_size: u32,
) -> sgx_status_t {
	let shard_identifier =
		ShardIdentifier::from_slice(slice::from_raw_parts(shard, shard_size as usize));
	let funding_balance = match Balance::decode(&mut slice::from_raw_parts(
		funding_balance,
		funding_balance_size as usize,
	)) {
		Ok(bal) => bal,
		Err(e) => {
			error!("Could not decode funding_balance: {:?}", e);
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
		init_proxied_shard_vault_internal(shard_identifier, parentchain_id, funding_balance)
	{
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

	let shard_vault = match get_shard_vault_internal(shard) {
		Ok((account, _)) => account,
		Err(e) => {
			warn!("Failed to fetch shard vault account: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};
	let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);
	pubkey_slice.clone_from_slice(shard_vault.encode().as_slice());
	sgx_status_t::SGX_SUCCESS
}

/// reads the shard vault account id form state if it has been initialized previously
pub(crate) fn get_shard_vault_internal(
	shard: ShardIdentifier,
) -> EnclaveResult<(AccountId, ParentchainId)> {
	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
	let (_state_lock, mut state) = state_handler.load_for_mutation(&shard)?;
	EnclaveStf::get_vault(&mut state).ok_or_else(|| {
		Error::Other("failed to fetch shard vault account. has it been initialized?".into())
	})
}

pub(crate) fn init_proxied_shard_vault_internal(
	shard: ShardIdentifier,
	parentchain_id: ParentchainId,
	funding_balance: Balance,
) -> EnclaveResult<()> {
	match parentchain_id {
		ParentchainId::Integritee => {
			let enclave_extrinsics_factory =
				get_extrinsic_factory_from_integritee_solo_or_parachain()?;
			let node_metadata_repo =
				get_node_metadata_repository_from_integritee_solo_or_parachain()?;
			init_shard(
				shard,
				parentchain_id,
				funding_balance,
				enclave_extrinsics_factory,
				node_metadata_repo,
			)
		},
		ParentchainId::TargetA => {
			let enclave_extrinsics_factory =
				get_extrinsic_factory_from_target_a_solo_or_parachain()?;
			let node_metadata_repo =
				get_node_metadata_repository_from_target_a_solo_or_parachain()?;
			init_shard(
				shard,
				parentchain_id,
				funding_balance,
				enclave_extrinsics_factory,
				node_metadata_repo,
			)
		},
		ParentchainId::TargetB => {
			let enclave_extrinsics_factory =
				get_extrinsic_factory_from_target_b_solo_or_parachain()?;
			let node_metadata_repo =
				get_node_metadata_repository_from_target_b_solo_or_parachain()?;
			init_shard(
				shard,
				parentchain_id,
				funding_balance,
				enclave_extrinsics_factory,
				node_metadata_repo,
			)
		},
	}
}

fn init_shard<NodeRuntimeConfig, Tip>(
	shard: ShardIdentifier,
	parentchain_id: ParentchainId,
	funding_balance: Balance,
	enclave_extrinsics_factory: Arc<EnclaveExtrinsicsFactory<NodeRuntimeConfig, Tip>>,
	node_metadata_repository: Arc<EnclaveNodeMetadataRepository>,
) -> EnclaveResult<()>
where
	NodeRuntimeConfig: Config<Hash = H256>,
	u128: From<Tip>,
	Tip: Copy + Default + Encode + Debug,
{
	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
	if !state_handler
		.shard_exists(&shard)
		.map_err(|_| Error::Other("get shard_exists failed".into()))?
	{
		return Err(Error::Other("shard not initialized".into()))
	};

	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;
	let enclave_signer = GLOBAL_SIGNING_KEY_REPOSITORY_COMPONENT.get()?.retrieve_key()?;

	let vault = enclave_signer
		.derive(vec![DeriveJunction::hard(shard.encode())].into_iter(), None)
		.map_err(|_| Error::Other("failed to derive shard vault keypair".into()))?
		.0;
	info!("shard vault account derived pubkey: 0x{}", hex::encode(vault.public().0));
	let (state_lock, mut state) = state_handler.load_for_mutation(&shard)?;
	EnclaveStf::init_shard_vault_account(&mut state, vault.public().into(), parentchain_id)
		.map_err(|e| Error::Stf(e.to_string()))?;
	state_handler.write_after_mutation(state, state_lock, &shard)?;

	info!(
		"[{:?}] send existential funds from enclave account to vault account: {:?}",
		parentchain_id, funding_balance
	);
	let call_ids = node_metadata_repository
		.get_from_metadata(|m| m.call_indexes("Balances", "transfer_keep_alive"))?
		.map_err(MetadataProviderError::MetadataError)?;

	let call = OpaqueCall::from_tuple(&(
		call_ids,
		Address::from(AccountId::from(vault.public().0)),
		Compact(funding_balance),
	));

	info!("[{:?}] vault funding call: 0x{}", parentchain_id, hex::encode(call.0.clone()));
	let mortality = try_mortality(64, &ocall_api, parentchain_id);
	let xts = enclave_extrinsics_factory.create_extrinsics(&[(call, mortality)], None)?;

	//this extrinsic must be included in a block before we can move on. otherwise the next will fail
	ocall_api.send_to_parentchain(xts, &parentchain_id, true)?;

	// double-check if vault has been initialized previously
	let responses = ocall_api.worker_request::<Header, Nonce>(
		vec![WorkerRequest::NextNonceFor(vault.public().into())],
		&parentchain_id,
	)?;
	if let Some(WorkerResponse::NextNonce(Some(nonce))) = responses.get(0) {
		if *nonce > 0 {
			warn!("The vault nonce is > 0. This means the shard has been initialized previously but this worker seems to have forgotten about it. Did you do a clean-reset of an already initialized shard? Continuing without re-registering proxy");
			return Ok(())
		}
	}
	let nonce_cache = Arc::new(NonceCache::default());
	let vault_extrinsics_factory = enclave_extrinsics_factory
		.with_signer(StaticExtrinsicSigner::<_, PairSignature>::new(vault), nonce_cache);

	info!("[{:?}] register enclave signer as proxy for shard vault", parentchain_id);
	let call_ids = node_metadata_repository
		.get_from_metadata(|m| m.call_indexes("Proxy", "add_proxy"))?
		.map_err(MetadataProviderError::MetadataError)?;

	let call = OpaqueCall::from_tuple(&(
		call_ids,
		Address::from(AccountId::from(enclave_signer.public().0)),
		ProxyType::Any,
		0u32, // delay
	));

	info!("[{:?}] add proxy call: 0x{}", parentchain_id, hex::encode(call.0.clone()));
	let mortality = try_mortality(64, &ocall_api, parentchain_id);
	let xts = vault_extrinsics_factory.create_extrinsics(&[(call, mortality)], None)?;

	ocall_api.send_to_parentchain(xts, &parentchain_id, true)?;
	info!("[{:?}] add proxy call got included", parentchain_id);
	Ok(())
}

pub(crate) fn add_shard_vault_proxy(
	shard: ShardIdentifier,
	proxy: &AccountId,
) -> EnclaveResult<()> {
	let (vault, parentchain_id) = get_shard_vault_internal(shard)?;

	match parentchain_id {
		ParentchainId::Integritee => {
			let enclave_extrinsics_factory =
				get_extrinsic_factory_from_integritee_solo_or_parachain()?;
			let node_metadata_repo =
				get_node_metadata_repository_from_integritee_solo_or_parachain()?;
			add_shard_vault_proxy_int(
				shard,
				proxy,
				vault,
				parentchain_id,
				enclave_extrinsics_factory,
				node_metadata_repo,
			)
		},
		ParentchainId::TargetA => {
			let enclave_extrinsics_factory =
				get_extrinsic_factory_from_target_a_solo_or_parachain()?;
			let node_metadata_repo =
				get_node_metadata_repository_from_target_a_solo_or_parachain()?;
			add_shard_vault_proxy_int(
				shard,
				proxy,
				vault,
				parentchain_id,
				enclave_extrinsics_factory,
				node_metadata_repo,
			)
		},
		ParentchainId::TargetB => {
			let enclave_extrinsics_factory =
				get_extrinsic_factory_from_target_b_solo_or_parachain()?;
			let node_metadata_repo =
				get_node_metadata_repository_from_target_b_solo_or_parachain()?;
			add_shard_vault_proxy_int(
				shard,
				proxy,
				vault,
				parentchain_id,
				enclave_extrinsics_factory,
				node_metadata_repo,
			)
		},
	}
}

fn add_shard_vault_proxy_int<NodeRuntimeConfig, Tip>(
	shard: ShardIdentifier,
	proxy: &AccountId,
	vault: AccountId,
	parentchain_id: ParentchainId,
	enclave_extrinsics_factory: Arc<EnclaveExtrinsicsFactory<NodeRuntimeConfig, Tip>>,
	node_metadata_repository: Arc<EnclaveNodeMetadataRepository>,
) -> EnclaveResult<()>
where
	NodeRuntimeConfig: Config<Hash = H256>,
	u128: From<Tip>,
	Tip: Copy + Default + Encode + Debug,
{
	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
	if !state_handler
		.shard_exists(&shard)
		.map_err(|_| Error::Other("get shard_exists failed".into()))?
	{
		return Err(Error::Other("shard not initialized".into()))
	};

	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;

	debug!(
		"adding proxy 0x{} to shard vault account 0x{} on {:?}",
		hex::encode(proxy.clone()),
		hex::encode(vault.clone()),
		parentchain_id,
	);

	let add_proxy_call = OpaqueCall::from_tuple(&(
		node_metadata_repository.get_from_metadata(|m| m.add_proxy_call_indexes())??,
		Address::from(proxy.clone()),
		ProxyType::Any,
		0u32, // delay
	));
	let call = OpaqueCall::from_tuple(&(
		node_metadata_repository.get_from_metadata(|m| m.proxy_call_indexes())??,
		Address::from(vault),
		None::<ProxyType>,
		add_proxy_call,
	));

	info!("proxied add proxy call: 0x{}", hex::encode(call.0.clone()));
	let mortality = try_mortality(64, &ocall_api, parentchain_id);
	let xts = enclave_extrinsics_factory.create_extrinsics(&[(call, mortality)], None)?;

	ocall_api.send_to_parentchain(xts, &ParentchainId::Integritee, false)?;
	Ok(())
}
