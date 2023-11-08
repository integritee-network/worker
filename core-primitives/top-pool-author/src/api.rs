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
use itp_stf_primitives::{
	traits::{PoolTransactionValidation, TrustedCallVerification},
	types::ShardIdentifier,
};
use itp_top_pool::{
	pool::{ChainApi, NumberFor},
	primitives::{TrustedOperationSource, TxHash},
};
use itp_types::BlockHash as SidechainBlockHash;
use jsonrpc_core::futures::future::{ready, Future, Ready};
use log::*;
use sp_runtime::{
	generic::BlockId,
	traits::{BlakeTwo256, Block as BlockT, Hash as HashT},
	transaction_validity::TransactionValidity,
};
use std::{boxed::Box, marker::PhantomData, pin::Pin};

/// Future that resolves to account nonce.
pub type Result<T> = core::result::Result<T, ()>;

/// The operation pool logic for full client.
pub struct SidechainApi<Block, TCS> {
	_marker: PhantomData<(Block, TCS)>,
}

impl<Block, TCS> SidechainApi<Block, TCS>
where
	TCS: PartialEq + TrustedCallVerification + Debug,
{
	/// Create new operation pool logic.
	pub fn new() -> Self {
		SidechainApi { _marker: Default::default() }
	}
}

impl<Block, TCS> Default for SidechainApi<Block, TCS>
where
	TCS: PartialEq + TrustedCallVerification + Debug + Sync + Send,
{
	fn default() -> Self {
		Self::new()
	}
}

impl<Block, TCS> ChainApi for SidechainApi<Block, TCS>
where
	Block: BlockT,
	TCS: PartialEq + TrustedCallVerification + Sync + Send + Debug,
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
	use itp_stf_primitives::types::ShardIdentifier;
	use itp_test::mock::stf_mock::{
		mock_top_indirect_trusted_call_signed, mock_top_public_getter, TrustedCallSignedMock,
	};
	use itp_types::{AccountId, Block as ParentchainBlock};
	use sp_core::{ed25519, Pair};

	type TestChainApi = SidechainApi<ParentchainBlock, TrustedCallSignedMock>;

	type Seed = [u8; 32];
	const TEST_SEED: Seed = *b"12345678901234567890123456789012";

	pub fn endowed_account() -> ed25519::Pair {
		ed25519::Pair::from_seed(&[42u8; 32].into())
	}

	#[test]
	fn indirect_calls_are_valid() {
		let chain_api = TestChainApi::default();
		let _account: AccountId = endowed_account().public().into();
		let operation = mock_top_indirect_trusted_call_signed();

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
		let public_getter = mock_top_public_getter();

		let validation = executor::block_on(chain_api.validate_transaction(
			TrustedOperationSource::Local,
			public_getter,
			ShardIdentifier::default(),
		))
		.unwrap();

		assert!(validation.is_err());
	}
}
