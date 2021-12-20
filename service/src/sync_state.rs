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

//! Handles all state syncing mission of a worker before start up.
use crate::enclave::tls_ra::enclave_request_key_provisioning;
use codec::Error as CodecError;
use futures::executor;
use itc_rpc_client::direct_client::{
	DirectApi, DirectClient as DirectWorkerApi, Error as DirectRpcClientError,
};
use itp_api_client_extensions::PalletTeerexApi;
use itp_enclave_api::remote_attestation::TlsRemoteAttestation;
use itp_types::ShardIdentifier;
use log::*;
use sgx_types::sgx_quote_sign_type_t;
use std::string::String;
use substrate_api_client::ApiClientError;

#[derive(Debug, thiserror::Error)]
enum Error {
	#[error("ApiClient Error: {0}")]
	ApiClient(#[from] ApiClientError),
	#[error("{0}")]
	Codec(#[from] CodecError),
	#[error("Could not fetch any data.")]
	EmptyValue,
	#[error("{0}")]
	JsonRpSeeClient(#[from] jsonrpsee::types::Error),
	#[error("{0}")]
	Serialization(#[from] serde_json::Error),
	#[error("{0}")]
	DirectRpcClient(#[from] DirectRpcClientError),
}

type StateSyncResult<T> = Result<T, Error>;

pub(crate) fn request_keys<E: TlsRemoteAttestation, NodeApi: PalletTeerexApi>(
	node_api: &NodeApi,
	shard: &ShardIdentifier,
	enclave_api: &E,
	skip_ra: bool,
) {
	// FIXME: we now assume that keys are equal for all shards

	// initialize the enclave
	#[cfg(feature = "production")]
	println!("*** Starting enclave in production mode");
	#[cfg(not(feature = "production"))]
	println!("*** Starting enclave in development mode");

	let provider_url =
		executor::block_on(get_author_url_of_last_finalized_sidechain_block(node_api, shard))
			.unwrap();
	println!("Requesting key provisioning from worker at {}", &provider_url);

	enclave_request_key_provisioning(
		enclave_api,
		sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
		&provider_url,
		skip_ra,
	)
	.unwrap();
	println!("[+] Key provisioning successfully performed.");
}

/// Returns the url of the last sidechain block author that has been stored
/// in the parentchain state as "worker for shard".
///
/// Note: The sidechainblock author will only change whenever a new parentchain block is
/// produced. And even then, it might be the same as the last block. So if several workers
/// are started in a timely manner, they all will all get the same url.
async fn get_author_url_of_last_finalized_sidechain_block<NodeApi: PalletTeerexApi>(
	node_api: &NodeApi,
	shard: &ShardIdentifier,
) -> StateSyncResult<String> {
	let enclave = node_api.worker_for_shard(shard)?.ok_or(Error::EmptyValue)?;
	let worker_api_direct = DirectWorkerApi::new(enclave.url);
	Ok(worker_api_direct.get_mu_ra_url()?)
}
