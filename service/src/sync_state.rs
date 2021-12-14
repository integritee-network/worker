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
use itp_enclave_api::remote_attestation::TlsRemoteAttestation;
use itp_types::ShardIdentifier;
use sgx_types::sgx_quote_sign_type_t;

pub(crate) fn request_keys<E: TlsRemoteAttestation>(
	provider_url: &str,
	_shard: &ShardIdentifier,
	enclave_api: &E,
	skip_ra: bool,
) {
	// FIXME: we now assume that keys are equal for all shards

	// initialize the enclave
	#[cfg(feature = "production")]
	println!("*** Starting enclave in production mode");
	#[cfg(not(feature = "production"))]
	println!("*** Starting enclave in development mode");

	println!("Requesting key provisioning from worker at {}", provider_url);

	enclave_request_key_provisioning(
		enclave_api,
		sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
		provider_url,
		skip_ra,
	)
	.unwrap();
	println!("key provisioning successfully performed");
}
