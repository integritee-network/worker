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
use itp_enclave_api::{enclave_base::EnclaveBase, remote_attestation::TlsRemoteAttestation};
use itp_node_api::api_client::PalletTeerexApi;
use itp_settings::worker_mode::{ProvideWorkerMode, WorkerMode};
use itp_types::ShardIdentifier;
use sgx_types::sgx_quote_sign_type_t;
use std::string::String;

pub(crate) fn sync_state<
	E: TlsRemoteAttestation + EnclaveBase,
	NodeApi: PalletTeerexApi,
	WorkerModeProvider: ProvideWorkerMode,
>(
	node_api: &NodeApi,
	shard: &ShardIdentifier,
	enclave_api: &E,
	skip_ra: bool,
) {
	// FIXME: we now assume that keys are equal for all shards.
	let provider_url = match WorkerModeProvider::worker_mode() {
		WorkerMode::Sidechain =>
			executor::block_on(get_author_url_of_last_finalized_sidechain_block(node_api, shard))
				.expect("Author of last finalized sidechain block could not be found"),
		_ => executor::block_on(get_enclave_url_of_first_registered(node_api, enclave_api))
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
		.worker_for_shard(shard, None)?
		.ok_or_else(|| Error::NoWorkerForShardFound(*shard))?;
	let worker_api_direct = DirectWorkerApi::new(enclave.url);
	Ok(worker_api_direct.get_mu_ra_url()?)
}

/// Returns the url of the first Enclave that matches our own MRENCLAVE.
///
/// This should be run before we register ourselves as enclave, to ensure we don't get our own url.
async fn get_enclave_url_of_first_registered<NodeApi: PalletTeerexApi, EnclaveApi: EnclaveBase>(
	node_api: &NodeApi,
	enclave_api: &EnclaveApi,
) -> Result<String> {
	let self_mr_enclave = enclave_api.get_mrenclave()?;
	let first_enclave = node_api
		.all_enclaves(None)?
		.into_iter()
		.find(|e| e.mr_enclave == self_mr_enclave)
		.ok_or(Error::NoPeerWorkerFound)?;
	let worker_api_direct = DirectWorkerApi::new(first_enclave.url);
	Ok(worker_api_direct.get_mu_ra_url()?)
}
