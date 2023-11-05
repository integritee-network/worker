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

use crate::types::{AccountId, KeyPair, ShardIdentifier};
use itp_sgx_runtime_primitives::types::Index;
use sp_runtime::transaction_validity::{TransactionValidityError, ValidTransaction};
/// checks authorization of stf getters
pub trait GetterAuthorization {
	fn is_authorized(&self) -> bool;
}

/// knows how to sign a trusted call input and provides a signed output
pub trait TrustedCallSigning {
	type Output;
	fn sign(
		&self,
		pair: &KeyPair,
		nonce: Index,
		mrenclave: &[u8; 32],
		shard: &ShardIdentifier,
	) -> Self::Output;
}

/// enables TrustedCallSigned verification
pub trait TrustedCallVerification {
	fn sender_account(&self) -> &AccountId;

	fn nonce(&self) -> Index;

	fn verify_signature(&self, mrenclave: &[u8; 32], shard: &ShardIdentifier) -> bool;
}

/// validation for top pool
pub trait PoolTransactionValidation {
	fn validate(&self) -> Result<ValidTransaction, TransactionValidityError>;
}
