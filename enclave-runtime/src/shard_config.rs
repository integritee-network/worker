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
		get_extrinsic_factory_from_target_a_solo_or_parachain,
		get_extrinsic_factory_from_target_b_solo_or_parachain,
		get_node_metadata_repository_from_integritee_solo_or_parachain,
		get_node_metadata_repository_from_target_a_solo_or_parachain,
		get_node_metadata_repository_from_target_b_solo_or_parachain,
		get_stf_enclave_signer_from_solo_or_parachain, DecodeRaw,
	},
};
use codec::{Compact, Decode, Encode};
use enclave_bridge_primitives::ShardConfig;
use itp_component_container::ComponentGetter;
use itp_extrinsics_factory::CreateExtrinsics;
use itp_node_api::{
	api_client::{PairSignature, StaticExtrinsicSigner},
	metadata::{
		pallet_enclave_bridge::EnclaveBridgeCallIndexes,
		pallet_proxy::PROXY_DEPOSIT,
		provider::{AccessNodeMetadata, Error as MetadataProviderError},
	},
};
use itp_node_api_metadata::pallet_proxy::ProxyCallIndexes;
use itp_nonce_cache::NonceCache;
use itp_ocall_api::{EnclaveAttestationOCallApi, EnclaveOnChainOCallApi};
use itp_sgx_crypto::key_repository::AccessKey;
use itp_stf_interface::SHARD_VAULT_KEY;
use itp_stf_state_handler::{handle_state::HandleState, query_shard_state::QueryShardState};
use itp_types::{
	parentchain::{AccountId, Address, BlockNumber, Header, ParentchainId, ProxyType},
	OpaqueCall, ShardIdentifier,
};
use itp_utils::hex::hex_encode;
use log::*;
use sgx_types::sgx_status_t;
use sp_core::crypto::{DeriveJunction, Pair};
use std::{slice, sync::Arc, vec::Vec};
use teerex_primitives::EnclaveFingerprint;

pub(crate) fn init_shard_config(shard: ShardIdentifier) -> EnclaveResult<()> {
	trace!("Intializing shard config on integritee network");
	let extrinsics_factory = get_extrinsic_factory_from_integritee_solo_or_parachain()?;
	let enclave_signer = get_stf_enclave_signer_from_solo_or_parachain()?;
	let mrenclave = enclave_signer.ocall_api.get_mrenclave_of_self()?;
	let shard_config = ShardConfig::<AccountId>::new(EnclaveFingerprint::from(mrenclave.m));

	let call = extrinsics_factory
		.node_metadata_repository
		.get_from_metadata(|m| m.update_shard_config_call_indexes())
		.map_err(|e| Error::Other(e.into()))?
		.map_err(|e| Error::Other(format!("{:?}", e).into()))?;

	let opaque_call = OpaqueCall::from_tuple(&(call, shard, shard_config, BlockNumber::from(0u8)));
	debug!("encoded call: {}", hex_encode(opaque_call.encode().as_slice()));
	let xts = extrinsics_factory
		.create_extrinsics(&[opaque_call], None)
		.map_err(|e| Error::Other(e.into()))?;

	info!("Initializing or touching shard config on integritee network. awaiting inclusion before continuing");
	// this needs to be blocking because the parentchain handler may be re-initialized right after this and the extrinsic would be swallowed
	enclave_signer
		.ocall_api
		.send_to_parentchain(xts, &ParentchainId::Integritee, true)
		.map_err(|e| Error::Other(e.into()))?;
	Ok(())
}
