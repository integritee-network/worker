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
use ita_stf::{AccountId, KeyPair, ShardIdentifier, TrustedCall, TrustedCallSigned};
use sp_core::Pair;

/// Mock for the StfExecutor.
#[derive(Default)]
pub struct StfExecutorMock;

pub struct StfRootOperationsMock {
	mr_enclave: [u8; 32],
}

impl StfRootOperationsMock {
	pub fn new(mr_enclave: [u8; 32]) -> Self {
		Self { mr_enclave }
	}
}

impl Default for StfRootOperationsMock {
	fn default() -> Self {
		Self::new([0u8; 32])
	}
}

impl StfRootOperations for StfRootOperationsMock {
	fn get_root_account(&self, _shard: &ShardIdentifier) -> Result<AccountId> {
		Ok(AccountId::new([42u8; 32]))
	}

	fn sign_call_with_root(
		&self,
		trusted_call: &TrustedCall,
		shard: &ShardIdentifier,
	) -> Result<TrustedCallSigned> {
		type Seed = [u8; 32];
		const TEST_SEED: Seed = *b"42345678901234567890123456789012";
		let signer = sp_core::ed25519::Pair::from_seed(&TEST_SEED);

		Ok(trusted_call.sign(&KeyPair::Ed25519(signer), 1, &self.mr_enclave, shard))
	}
}
