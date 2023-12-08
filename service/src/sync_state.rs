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

//! Request state keys from a fellow validateer.

use crate::{
	enclave::tls_ra::enclave_request_state_provisioning,
	error::{Error, ServiceResult as Result},
};
use futures::executor;
use itc_rpc_client::direct_client::{DirectApi, DirectClient as DirectWorkerApi};
use itp_enclave_api::{
	enclave_base::EnclaveBase,
	remote_attestation::{RemoteAttestation, TlsRemoteAttestation},
};
use itp_node_api::api_client::PalletTeerexApi;
use itp_settings::worker_mode::{ProvideWorkerMode, WorkerMode};
use itp_types::{parentchain::AccountId, ShardIdentifier};
use log::info;
use sgx_types::sgx_quote_sign_type_t;
use sp_runtime::MultiSigner;
use std::string::String;
use teerex_primitives::AnySigner;

pub(crate) fn sync_state<
	E: TlsRemoteAttestation + EnclaveBase + RemoteAttestation,
	NodeApi: PalletTeerexApi,
	WorkerModeProvider: ProvideWorkerMode,
>(
	node_api: &NodeApi,
	shard: &ShardIdentifier,
	enclave_api: &E,
	skip_ra: bool,
) {
	let provider_url = match WorkerModeProvider::worker_mode() {
		WorkerMode::Sidechain | WorkerMode::OffChainWorker =>
			executor::block_on(get_enclave_url_of_last_active(node_api, enclave_api, shard))
				.expect("author of most recent shard update not found"),
		WorkerMode::Teeracle =>
			executor::block_on(get_enclave_url_of_first_registered(node_api, enclave_api))
				.expect("Author of last finalized sidechain block could not be found"),
	};

	println!("Requesting state provisioning from worker at {}", &provider_url);

	enclave_request_state_provisioning(
		enclave_api,
		sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
		&provider_url,
		shard,
		skip_ra,
	)
	.unwrap();
	println!("[+] State provisioning successfully performed.");
}

/// Returns the url of the last sidechain block author that has been stored
/// in the parentchain state as "worker for shard".
///
/// Note: The sidechainblock author will only change whenever a new parentchain block is
/// produced. And even then, it might be the same as the last block. So if several workers
/// are started in a timely manner, they will all get the same url.
async fn get_author_url_of_last_finalized_sidechain_block<NodeApi: PalletTeerexApi>(
	node_api: &NodeApi,
	shard: &ShardIdentifier,
) -> Result<String> {
	let enclave = node_api
		.primary_worker_for_shard(shard, None)?
		.ok_or_else(|| Error::NoWorkerForShardFound(*shard))?;
	let worker_api_direct =
		DirectWorkerApi::new(String::from_utf8(enclave.instance_url().unwrap()).unwrap());
	Ok(worker_api_direct.get_mu_ra_url()?)
}

/// Returns the url of the first Enclave that matches our own MRENCLAVE which isn't ourself.
/// this is not reliable because there may be other active peers although the very first one went offline
async fn get_enclave_url_of_first_registered<NodeApi: PalletTeerexApi, EnclaveApi: EnclaveBase>(
	node_api: &NodeApi,
	enclave_api: &EnclaveApi,
) -> Result<String> {
	let self_mr_enclave = enclave_api.get_fingerprint()?;
	let self_account = enclave_api.get_ecc_signing_pubkey()?;
	let first_enclave = node_api
		.all_enclaves(None)?
		.into_iter()
		.filter(|e| e.instance_signer() != AnySigner::Known(MultiSigner::Ed25519(self_account)))
		.find(|e| e.fingerprint() == self_mr_enclave)
		.ok_or(Error::NoPeerWorkerFound)?;
	let worker_api_direct =
		DirectWorkerApi::new(String::from_utf8(first_enclave.instance_url().unwrap()).unwrap());
	Ok(worker_api_direct.get_mu_ra_url()?)
}

/// Returns the url of the last active worker on our shard
async fn get_enclave_url_of_last_active<NodeApi: PalletTeerexApi, EnclaveApi: EnclaveBase>(
	node_api: &NodeApi,
	enclave_api: &EnclaveApi,
	shard: &ShardIdentifier,
) -> Result<String> {
	let self_account = enclave_api.get_ecc_signing_pubkey()?;
	let shard_status = node_api
		.shard_status(shard, None)
		.expect("must be able to fetch shard status")
		.expect("can only sync state for active shards");
	info!("fetching active peer. shard status: {:?}", shard_status);
	let last_active_signer_status = shard_status
		.iter()
		.filter(|&s| s.signer != AccountId::from(self_account))
		.max_by_key(|&signer_status| signer_status.last_activity)
		.expect("there has to be a most recently active peer")
		.clone();
	info!("most recently active signer on this shard: {:?}", last_active_signer_status);
	let provider_enclave = node_api
		.enclave(&last_active_signer_status.signer, None)
		.expect("must be able to fetch enclaves")
		.expect("active peer must exist in registry");
	let worker_api_direct = DirectWorkerApi::new(
		String::from_utf8(provider_enclave.instance_url().expect("provider must specify url"))
			.unwrap(),
	);
	Ok(worker_api_direct.get_mu_ra_url()?)
}
