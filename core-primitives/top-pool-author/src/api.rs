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

//! Chain api required for the operation pool.

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;
use core::fmt::Debug;

use crate::error;
use codec::Encode;
use ita_stf::{Getter, TrustedCallSigned};
use itp_stf_primitives::{
	traits::{PoolTransactionValidation, TrustedCallVerification},
	types::ShardIdentifier,
};
use itp_top_pool::{
	pool::{ChainApi, ExtrinsicHash, NumberFor},
	primitives::{TrustedOperationSource, TxHash},
};
use itp_types::BlockHash as SidechainBlockHash;
use jsonrpc_core::futures::future::{ready, Future, Ready};
use log::*;
use sp_runtime::{
	generic::BlockId,
	traits::{BlakeTwo256, Block as BlockT, Hash as HashT, Header as HeaderT},
	transaction_validity::{
		TransactionValidity, TransactionValidityError, UnknownTransaction, ValidTransaction,
	},
};
use std::{boxed::Box, marker::PhantomData, pin::Pin, vec, vec::Vec};

/// Future that resolves to account nonce.
pub type Result<T> = core::result::Result<T, ()>;

/// The operation pool logic for full client.
pub struct SidechainApi<Block, TCS> {
	_marker: PhantomData<(Block, TCS)>,
}

impl<Block, TCS> SidechainApi<Block, TCS>
where
	TCS: TrustedCallVerification,
{
	/// Create new operation pool logic.
	pub fn new() -> Self {
		SidechainApi { _marker: Default::default() }
	}
}

impl<Block, TCS> Default for SidechainApi<Block, TCS>
where
	TCS: TrustedCallVerification + Sync + Send,
{
	fn default() -> Self {
		Self::new()
	}
}

impl<Block, TCS> ChainApi for SidechainApi<Block, TCS>
where
	Block: BlockT,
	TCS: TrustedCallVerification + Sync + Send + Debug,
{
	type Block = Block;
	type Error = error::Error;
	type ValidationFuture =
		Pin<Box<dyn Future<Output = error::Result<TransactionValidity>> + Send>>;
	type BodyFuture = Ready<error::Result<Option<bool>>>;

	fn validate_transaction<TOP: PoolTransactionValidation>(
		&self,
		_source: TrustedOperationSource,
		uxt: TOP,
		_shard: ShardIdentifier,
	) -> Self::ValidationFuture {
		let operation = uxt.validate();
		Box::pin(ready(Ok(operation)))
	}

	fn block_id_to_number(
		&self,
		at: &BlockId<Self::Block>,
	) -> error::Result<Option<NumberFor<Self>>> {
		Ok(match at {
			BlockId::Number(num) => Some(*num),
			BlockId::Hash(_) => None,
		})
	}

	fn block_id_to_hash(
		&self,
		at: &BlockId<Self::Block>,
	) -> error::Result<Option<SidechainBlockHash>> {
		Ok(match at {
			//BlockId::Hash(x) => Some(x.clone()),
			BlockId::Hash(_x) => None,
			// dummy
			BlockId::Number(_num) => None,
		})
	}

	fn hash_and_length<TOP: Encode + Debug>(&self, ex: &TOP) -> (TxHash, usize) {
		debug!("[Pool] creating hash of {:?}", ex);
		ex.using_encoded(|x| (BlakeTwo256::hash(x), x.len()))
	}

	fn block_body<TOP>(&self, _id: &BlockId<Self::Block>) -> Self::BodyFuture {
		ready(Ok(None))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use futures::executor;
	use ita_stf::{PublicGetter, TrustedCall, TrustedOperation};
	use itp_stf_primitives::types::{KeyPair, ShardIdentifier};
	use itp_top_pool::mocks::trusted_operation_pool_mock::TrustedCallSignedMock;
	use itp_types::Block as ParentchainBlock;
	use sp_core::{ed25519, Pair};
	use sp_keyring::AccountKeyring;

	type TestChainApi = SidechainApi<ParentchainBlock, TrustedCallSignedMock>;

	type Seed = [u8; 32];
	const TEST_SEED: Seed = *b"12345678901234567890123456789012";

	#[test]
	fn indirect_calls_are_valid() {
		let chain_api = TestChainApi::default();
		let operation = TrustedOperationMock::indirect_call(TrustedCallSignedMock);

		let validation = executor::block_on(chain_api.validate_transaction(
			TrustedOperationSource::Local,
			operation,
			ShardIdentifier::default(),
		))
		.unwrap();

		assert!(validation.is_ok());
	}

	#[test]
	fn public_getters_are_not_valid() {
		let chain_api = TestChainApi::default();
		let public_getter = TrustedOperationMock::get(GetterMock);

		let validation = executor::block_on(chain_api.validate_transaction(
			TrustedOperationSource::Local,
			public_getter,
			ShardIdentifier::default(),
		))
		.unwrap();

		assert!(validation.is_err());
	}
}
