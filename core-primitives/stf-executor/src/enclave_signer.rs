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

use crate::{error::Result, traits::StfEnclaveSigning};
use ita_stf::{AccountId, Index, KeyPair, Stf, TrustedCall, TrustedCallSigned};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_sgx_crypto::{ed25519_derivation::DeriveEd25519, key_repository::AccessKey};
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_state_observer::traits::ObserveState;
use itp_types::ShardIdentifier;
use sp_core::{ed25519::Pair as Ed25519Pair, Pair};
use std::sync::Arc;

pub struct StfEnclaveSigner<OCallApi, StateObserver, ShieldingKeyRepository> {
	state_observer: Arc<StateObserver>,
	ocall_api: Arc<OCallApi>,
	shielding_key_repo: Arc<ShieldingKeyRepository>,
}

impl<OCallApi, StateObserver, ShieldingKeyRepository>
	StfEnclaveSigner<OCallApi, StateObserver, ShieldingKeyRepository>
where
	OCallApi: EnclaveAttestationOCallApi,
	StateObserver: ObserveState,
	StateObserver::StateType: SgxExternalitiesTrait,
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType: DeriveEd25519,
{
	pub fn new(
		state_observer: Arc<StateObserver>,
		ocall_api: Arc<OCallApi>,
		shielding_key_repo: Arc<ShieldingKeyRepository>,
	) -> Self {
		Self { state_observer, ocall_api, shielding_key_repo }
	}

	fn get_enclave_account_nonce(&self, shard: &ShardIdentifier) -> Result<Index> {
		let enclave_account = self.get_enclave_account()?;
		let nonce = self
			.state_observer
			.observe_state(shard, move |state| Stf::account_nonce(state, &enclave_account))?;

		Ok(nonce)
	}

	fn get_enclave_call_signing_key(&self) -> Result<Ed25519Pair> {
		let shielding_key = self.shielding_key_repo.retrieve_key()?;
		shielding_key.derive_ed25519().map_err(|e| e.into())
	}
}

impl<OCallApi, StateObserver, ShieldingKeyRepository> StfEnclaveSigning
	for StfEnclaveSigner<OCallApi, StateObserver, ShieldingKeyRepository>
where
	OCallApi: EnclaveAttestationOCallApi,
	StateObserver: ObserveState,
	StateObserver::StateType: SgxExternalitiesTrait,
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType: DeriveEd25519,
{
	fn get_enclave_account(&self) -> Result<AccountId> {
		let enclave_call_signing_key = self.get_enclave_call_signing_key()?;
		Ok(enclave_call_signing_key.public().into())
	}

	fn sign_call_with_self(
		&self,
		trusted_call: &TrustedCall,
		shard: &ShardIdentifier,
	) -> Result<TrustedCallSigned> {
		let mr_enclave = self.ocall_api.get_mrenclave_of_self()?;
		let enclave_account_nonce = self.get_enclave_account_nonce(shard)?;
		let enclave_call_signing_key = self.get_enclave_call_signing_key()?;

		Ok(trusted_call.sign(
			&KeyPair::Ed25519(enclave_call_signing_key),
			enclave_account_nonce,
			&mr_enclave.m,
			shard,
		))
	}
}
