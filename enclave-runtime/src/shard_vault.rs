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
		EnclaveBlockImportConfirmationHandler, EnclaveGetterExecutor, EnclaveLightClientSeal,
		EnclaveOCallApi, EnclaveRpcConnectionRegistry, EnclaveRpcResponder,
		EnclaveShieldingKeyRepository, EnclaveSidechainApi, EnclaveSidechainBlockImportQueue,
		EnclaveSidechainBlockImportQueueWorker, EnclaveSidechainBlockImporter,
		EnclaveSidechainBlockSyncer, EnclaveStateFileIo, EnclaveStateHandler,
		EnclaveStateInitializer, EnclaveStateObserver, EnclaveStateSnapshotRepository,
		EnclaveStfEnclaveSigner, EnclaveTopPool, EnclaveTopPoolAuthor,
		GLOBAL_ATTESTATION_HANDLER_COMPONENT, GLOBAL_INTEGRITEE_PARENTCHAIN_LIGHT_CLIENT_SEAL,
		GLOBAL_OCALL_API_COMPONENT, GLOBAL_RPC_WS_HANDLER_COMPONENT,
		GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT, GLOBAL_SIDECHAIN_BLOCK_COMPOSER_COMPONENT,
		GLOBAL_SIDECHAIN_BLOCK_SYNCER_COMPONENT, GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT,
		GLOBAL_SIDECHAIN_IMPORT_QUEUE_WORKER_COMPONENT, GLOBAL_SIGNING_KEY_REPOSITORY_COMPONENT,
		GLOBAL_STATE_HANDLER_COMPONENT, GLOBAL_STATE_KEY_REPOSITORY_COMPONENT,
		GLOBAL_STATE_OBSERVER_COMPONENT, GLOBAL_TARGET_A_PARENTCHAIN_LIGHT_CLIENT_SEAL,
		GLOBAL_TARGET_B_PARENTCHAIN_LIGHT_CLIENT_SEAL, GLOBAL_TOP_POOL_AUTHOR_COMPONENT,
		GLOBAL_WEB_SOCKET_SERVER_COMPONENT,
	},
	ocall::OcallApi,
	rpc::{rpc_response_channel::RpcResponseChannel, worker_api_direct::public_api_rpc_handler},
	utils::{
		get_extrinsic_factory_from_integritee_solo_or_parachain,
		get_node_metadata_repository_from_integritee_solo_or_parachain,
		get_triggered_dispatcher_from_solo_or_parachain,
		get_validator_accessor_from_solo_or_parachain,
	},
	Hash,
};
use base58::ToBase58;
use codec::{Compact, Encode};
use itc_direct_rpc_server::{
	create_determine_watch, rpc_connection_registry::ConnectionRegistry,
	rpc_ws_handler::RpcWsHandler,
};
use itc_tls_websocket_server::{
	certificate_generation::ed25519_self_signed_certificate, create_ws_server, ConnectionToken,
	WebSocketServer,
};
use itp_attestation_handler::IntelAttestationHandler;
use itp_component_container::{ComponentGetter, ComponentInitializer};
use itp_extrinsics_factory::CreateExtrinsics;
use itp_node_api::{
	api_client::{PairSignature, StaticExtrinsicSigner},
	metadata::{
		pallet_proxy::PROXY_DEPOSIT,
		provider::{AccessNodeMetadata, Error as MetadataProviderError},
	},
};
use itp_nonce_cache::NonceCache;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_primitives_cache::GLOBAL_PRIMITIVES_CACHE;
use itp_settings::files::{
	INTEGRITEE_PARENTCHAIN_LIGHT_CLIENT_DB_PATH, STATE_SNAPSHOTS_CACHE_SIZE,
	TARGET_A_PARENTCHAIN_LIGHT_CLIENT_DB_PATH, TARGET_B_PARENTCHAIN_LIGHT_CLIENT_DB_PATH,
};
use itp_sgx_crypto::{
	get_aes_repository, get_ed25519_repository, get_rsa3072_repository, key_repository::AccessKey,
};
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_interface::SHARD_VAULT_KEY;
use itp_stf_state_handler::{
	file_io::StateDir, handle_state::HandleState, query_shard_state::QueryShardState,
	state_snapshot_repository::VersionedStateAccess,
	state_snapshot_repository_loader::StateSnapshotRepositoryLoader, StateHandler,
};
use itp_top_pool::pool::Options as PoolOptions;
use itp_top_pool_author::author::AuthorTopFilter;
use itp_types::{
	parentchain::{AccountId, Address, Balance, ParentchainId, ProxyType},
	OpaqueCall, ShardIdentifier,
};
use its_sidechain::block_composer::BlockComposer;
use log::*;
use sgx_types::sgx_status_t;
use sp_core::{
	blake2_256,
	crypto::{DeriveJunction, Pair},
	ed25519,
};
use std::{collections::HashMap, path::PathBuf, slice, string::String, sync::Arc, vec::Vec};

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

	// todo

	//let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);
	//debug!("Restored ECC pubkey: {:?}", signer_public);
	//pubkey_slice.clone_from_slice(&vault_pubkey);
	sgx_status_t::SGX_ERROR_UNEXPECTED
}

/// reads the shard vault account id form state if it has been initialized previously
pub(crate) fn get_shard_vault_account(shard: ShardIdentifier) -> EnclaveResult<AccountId> {
	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;

	let vault_pubkey: Vec<u8> = state_handler
		.execute_on_current(&shard, |state, _| {
			let maybe_vault_key: Option<&Vec<u8>> =
				state.state.get::<Vec<u8>>(&SHARD_VAULT_KEY.into());
			maybe_vault_key.unwrap().clone()
		})
		.unwrap();

	Err(Error::Other("unimplemented".into()))
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
		.map_err(|e| Error::Other("failed to derive shard vault keypair".into()))?
		.0;

	info!("shard vault account derived pubkey: 0x{}", hex::encode(vault.public().0.clone()));

	let (state_lock, mut state) = state_handler.load_for_mutation(&shard)?;
	state.state.insert(SHARD_VAULT_KEY.into(), vault.public().0.to_vec());
	state_handler.write_after_mutation(state, state_lock, &shard)?;
	// todo!
	// parentchain-query: if shard vault not yet existing or self not proxy:

	// xt: send funds from enclave account to new vault account (panic if not enough funds)

	info!("send existential funds from enclave account to vault account");
	let call_ids = node_metadata_repo
		.get_from_metadata(|m| m.call_indexes("Balances", "transfer_keep_alive"))?
		.map_err(MetadataProviderError::MetadataError)?;

	let call = OpaqueCall::from_tuple(&(
		call_ids,
		Address::from(AccountId::from(vault.public().0)),
		Compact(Balance::from(PROXY_DEPOSIT)),
	));

	info!("vault funding call: 0x{}", hex::encode(call.0.clone()));
	let xts = enclave_extrinsics_factory.create_extrinsics(&[call], None)?;

	//this extrinsic must be included in a block before we can move on. otherwise the next will fail
	ocall_api.send_to_parentchain(xts, &ParentchainId::Integritee, true);

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

	ocall_api.send_to_parentchain(xts, &ParentchainId::Integritee, false);

	// xt: delegate proxy authority to its own enclave accountid proxy.add_proxy() (panic if fails)
	// caveat: must send from vault account. how to sign extrinsics with other keypair?
	// sth like: extrinsics_factory.with_signer(keypair).create_extrinsics(
	// write vault accountid to STF State (SgxExternalitiesType) with key ShardVaultAccountId to make it available also beyond service restart for non-primary SCV later
	// return and log vault accountId
	Ok(())
}

pub(crate) fn add_shard_vault_proxy(shard: ShardIdentifier, proxy: AccountId) -> EnclaveResult<()> {
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
		.map_err(|e| Error::Other("failed to derive shard vault keypair".into()))?
		.0;

	info!("shard vault account derived pubkey: 0x{}", hex::encode(vault.public().0.clone()));

	let (state_lock, mut state) = state_handler.load_for_mutation(&shard)?;
	state.state.insert(SHARD_VAULT_KEY.into(), vault.public().0.to_vec());
	state_handler.write_after_mutation(state, state_lock, &shard)?;
	// todo!
	// parentchain-query: if shard vault not yet existing or self not proxy:

	// xt: send funds from enclave account to new vault account (panic if not enough funds)

	info!("send existential funds from enclave account to vault account");
	let call_ids = node_metadata_repo
		.get_from_metadata(|m| m.call_indexes("Balances", "transfer_keep_alive"))?
		.map_err(MetadataProviderError::MetadataError)?;

	let call = OpaqueCall::from_tuple(&(
		call_ids,
		Address::from(AccountId::from(vault.public().0)),
		Compact(Balance::from(PROXY_DEPOSIT)),
	));

	info!("vault funding call: 0x{}", hex::encode(call.0.clone()));
	let xts = enclave_extrinsics_factory.create_extrinsics(&[call], None)?;

	//this extrinsic must be included in a block before we can move on. otherwise the next will fail
	ocall_api.send_to_parentchain(xts, &ParentchainId::Integritee, true);

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

	ocall_api.send_to_parentchain(xts, &ParentchainId::Integritee, false);

	// xt: delegate proxy authority to its own enclave accountid proxy.add_proxy() (panic if fails)
	// caveat: must send from vault account. how to sign extrinsics with other keypair?
	// sth like: extrinsics_factory.with_signer(keypair).create_extrinsics(
	// write vault accountid to STF State (SgxExternalitiesType) with key ShardVaultAccountId to make it available also beyond service restart for non-primary SCV later
	// return and log vault accountId
	Ok(())
}
