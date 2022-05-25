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
use itp_stf_state_handler::handle_state::HandleState;
use itp_types::ShardIdentifier;
use sgx_externalities::SgxExternalitiesTrait;
use sp_core::{ed25519::Pair as Ed25519Pair, Pair, H256};
use std::sync::Arc;

pub struct StfEnclaveSigner<OCallApi, StateHandler, SigningKey> {
	state_handler: Arc<StateHandler>,
	ocall_api: Arc<OCallApi>,
	signer: SigningKey,
}

impl<OCallApi, StateHandler> StfEnclaveSigner<OCallApi, StateHandler, Ed25519Pair>
where
	OCallApi: EnclaveAttestationOCallApi,
	StateHandler: HandleState<HashType = H256>,
	StateHandler::StateT: SgxExternalitiesTrait,
{
	pub fn new(
		state_handler: Arc<StateHandler>,
		ocall_api: Arc<OCallApi>,
		signer: Ed25519Pair,
	) -> Self {
		Self { state_handler, ocall_api, signer }
	}

	fn get_enclave_account_nonce(&self, shard: &ShardIdentifier) -> Result<Index> {
		let enclave_account = self.get_enclave_account();
		let mut state = self.state_handler.load(shard)?;
		let nonce = Stf::account_nonce(&mut state, &enclave_account);
		Ok(nonce)
	}
}

impl<OCallApi, StateHandler> StfEnclaveSigning
	for StfEnclaveSigner<OCallApi, StateHandler, Ed25519Pair>
where
	OCallApi: EnclaveAttestationOCallApi,
	StateHandler: HandleState<HashType = H256>,
	StateHandler::StateT: SgxExternalitiesTrait,
{
	fn get_enclave_account(&self) -> AccountId {
		self.signer.public().into()
	}

	fn sign_call_with_self(
		&self,
		trusted_call: &TrustedCall,
		shard: &ShardIdentifier,
	) -> Result<TrustedCallSigned> {
		let mr_enclave = self.ocall_api.get_mrenclave_of_self()?;
		let enclave_account_nonce = self.get_enclave_account_nonce(shard)?;

		Ok(trusted_call.sign(
			&KeyPair::Ed25519(self.signer.clone()),
			enclave_account_nonce,
			&mr_enclave.m,
			shard,
		))
	}
}
