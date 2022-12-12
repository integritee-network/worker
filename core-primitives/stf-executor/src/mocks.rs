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

use crate::{
	error::Result,
	state_getter::GetState,
	traits::{StateUpdateProposer, StfEnclaveSigning},
	BatchExecutionResult, ExecutedOperation,
};
use codec::Encode;
use ita_stf::{
	hash::{Hash, TrustedOperationOrHash},
	TrustedCall, TrustedCallSigned, TrustedGetterSigned, TrustedOperation,
};
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_primitives::types::{AccountId, KeyPair, ShardIdentifier};
use itp_types::H256;
use sp_core::Pair;
use sp_runtime::traits::Header as HeaderTrait;
use std::{boxed::Box, marker::PhantomData, ops::Deref, time::Duration, vec::Vec};

#[cfg(feature = "std")]
use std::sync::RwLock;

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

/// Mock for the StfExecutor.
#[derive(Default)]
pub struct StfExecutorMock<State> {
	pub state: RwLock<State>,
}

impl<State: Clone> StfExecutorMock<State> {
	pub fn new(state: State) -> Self {
		Self { state: RwLock::new(state) }
	}

	pub fn get_state(&self) -> State {
		(*self.state.read().unwrap().deref()).clone()
	}
}

impl<State> StateUpdateProposer for StfExecutorMock<State>
where
	State: SgxExternalitiesTrait + Encode + Clone,
{
	type Externalities = State;

	fn propose_state_update<PH, F>(
		&self,
		trusted_calls: &[TrustedOperation],
		_header: &PH,
		_shard: &ShardIdentifier,
		_max_exec_duration: Duration,
		prepare_state_function: F,
	) -> Result<BatchExecutionResult<Self::Externalities>>
	where
		PH: HeaderTrait<Hash = H256>,
		F: FnOnce(Self::Externalities) -> Self::Externalities,
	{
		let mut lock = self.state.write().unwrap();

		let updated_state = prepare_state_function((*lock.deref()).clone());

		*lock = updated_state.clone();

		let executed_operations: Vec<ExecutedOperation> = trusted_calls
			.iter()
			.map(|c| {
				let operation_hash = c.hash();
				let top_or_hash = TrustedOperationOrHash::from_top(c.clone());
				ExecutedOperation::success(operation_hash, top_or_hash, Vec::new())
			})
			.collect();

		Ok(BatchExecutionResult {
			executed_operations,
			state_hash_before_execution: H256::default(),
			state_after_execution: updated_state,
		})
	}
}

/// Enclave signer mock.
pub struct StfEnclaveSignerMock {
	mr_enclave: [u8; 32],
	signer: sp_core::ed25519::Pair,
}

impl StfEnclaveSignerMock {
	pub fn new(mr_enclave: [u8; 32]) -> Self {
		type Seed = [u8; 32];
		const TEST_SEED: Seed = *b"42345678901234567890123456789012";

		Self { mr_enclave, signer: sp_core::ed25519::Pair::from_seed(&TEST_SEED) }
	}
}

impl Default for StfEnclaveSignerMock {
	fn default() -> Self {
		Self::new([0u8; 32])
	}
}

impl StfEnclaveSigning for StfEnclaveSignerMock {
	fn get_enclave_account(&self) -> Result<AccountId> {
		Ok(self.signer.public().into())
	}

	fn sign_call_with_self(
		&self,
		trusted_call: &TrustedCall,
		shard: &ShardIdentifier,
	) -> Result<TrustedCallSigned> {
		Ok(trusted_call.sign(&KeyPair::Ed25519(Box::new(self.signer)), 1, &self.mr_enclave, shard))
	}
}

/// GetState mock
#[derive(Default)]
pub struct GetStateMock<StateType> {
	_phantom: PhantomData<StateType>,
}

impl<StateType> GetState<StateType> for GetStateMock<StateType>
where
	StateType: Encode,
{
	fn get_state(_getter: &TrustedGetterSigned, state: &mut StateType) -> Result<Option<Vec<u8>>> {
		Ok(Some(state.encode()))
	}
}
