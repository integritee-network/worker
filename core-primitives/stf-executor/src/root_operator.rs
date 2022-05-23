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

use crate::{error::Result, traits::StfRootOperations};
use ita_stf::{AccountId, Index, KeyPair, Stf, TrustedCall, TrustedCallSigned};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_stf_state_handler::handle_state::HandleState;
use itp_types::ShardIdentifier;
use sgx_externalities::SgxExternalitiesTrait;
use sp_core::{ed25519::Pair, H256};
use std::sync::Arc;

pub struct StfRootOperator<OCallApi, StateHandler, Signer> {
	state_handler: Arc<StateHandler>,
	ocall_api: Arc<OCallApi>,
	signer: Signer,
}

impl<OCallApi, StateHandler> StfRootOperator<OCallApi, StateHandler, Pair>
where
	OCallApi: EnclaveAttestationOCallApi,
	StateHandler: HandleState<HashType = H256>,
	StateHandler::StateT: SgxExternalitiesTrait,
{
	pub fn new(state_handler: Arc<StateHandler>, ocall_api: Arc<OCallApi>, signer: Pair) -> Self {
		Self { state_handler, ocall_api, signer }
	}

	fn get_root_nonce(&self, shard: &ShardIdentifier) -> Result<Index> {
		let mut state = self.state_handler.load(shard)?;
		let root = Stf::get_root(&mut state);
		let nonce = Stf::account_nonce(&mut state, &root);
		Ok(nonce)
	}
}

impl<OCallApi, StateHandler> StfRootOperations for StfRootOperator<OCallApi, StateHandler, Pair>
where
	OCallApi: EnclaveAttestationOCallApi,
	StateHandler: HandleState<HashType = H256>,
	StateHandler::StateT: SgxExternalitiesTrait,
{
	fn get_root_account(&self, shard: &ShardIdentifier) -> Result<AccountId> {
		let mut state = self.state_handler.load(shard)?;
		Ok(Stf::get_root(&mut state))
	}

	fn sign_call_with_root(
		&self,
		trusted_call: &TrustedCall,
		shard: &ShardIdentifier,
	) -> Result<TrustedCallSigned> {
		let mr_enclave = self.ocall_api.get_mrenclave_of_self()?;
		let root_nonce = self.get_root_nonce(shard)?;

		Ok(trusted_call.sign(
			&KeyPair::Ed25519(self.signer.clone()),
			root_nonce,
			&mr_enclave.m,
			shard,
		))
	}
}
