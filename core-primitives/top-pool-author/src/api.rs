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

use crate::error;
use codec::Encode;
use ita_stf::{Getter, ShardIdentifier, TrustedOperation as StfTrustedOperation};
use itp_top_pool::{
	pool::{ChainApi, ExtrinsicHash, NumberFor},
	primitives::TrustedOperationSource,
};
use itp_types::BlockHash as SidechainBlockHash;
use jsonrpc_core::futures::future::{ready, Future, Ready};
use log::*;
use sp_runtime::{
	generic::BlockId,
	traits::{Block as BlockT, Hash as HashT, Header as HeaderT},
	transaction_validity::{
		TransactionValidity, TransactionValidityError, UnknownTransaction, ValidTransaction,
	},
};
use std::{boxed::Box, marker::PhantomData, pin::Pin, vec, vec::Vec};

/// Future that resolves to account nonce.
pub type Result<T> = core::result::Result<T, ()>;

/// The operation pool logic for full client.
pub struct SidechainApi<Block> {
	_marker: PhantomData<Block>,
}

impl<Block> SidechainApi<Block> {
	/// Create new operation pool logic.
	pub fn new() -> Self {
		SidechainApi { _marker: Default::default() }
	}
}

impl<Block> Default for SidechainApi<Block> {
	fn default() -> Self {
		Self::new()
	}
}

impl<Block> ChainApi for SidechainApi<Block>
where
	Block: BlockT,
{
	type Block = Block;
	type Error = error::Error;
	type ValidationFuture =
		Pin<Box<dyn Future<Output = error::Result<TransactionValidity>> + Send>>;
	type BodyFuture = Ready<error::Result<Option<Vec<StfTrustedOperation>>>>;

	fn validate_transaction(
		&self,
		_source: TrustedOperationSource,
		uxt: StfTrustedOperation,
		_shard: ShardIdentifier,
	) -> Self::ValidationFuture {
		let operation = match uxt {
			StfTrustedOperation::direct_call(signed_call) => {
				let from = signed_call.call.account();
				let requires = vec![];
				let provides = vec![from.encode()];

				ValidTransaction {
					priority: 1 << 20,
					requires,
					provides,
					longevity: 64,
					propagate: true,
				}
			},
			StfTrustedOperation::get(getter) => match getter {
				Getter::public(_) =>
					return Box::pin(ready(Ok(Err(TransactionValidityError::Unknown(
						UnknownTransaction::CannotLookup,
					))))),
				Getter::trusted(trusted_getter) => ValidTransaction {
					priority: 1 << 20,
					requires: vec![],
					provides: vec![trusted_getter.signature.encode()],
					longevity: 64,
					propagate: true,
				},
			},
			_ =>
				return Box::pin(ready(Ok(Err(TransactionValidityError::Unknown(
					UnknownTransaction::CannotLookup,
				))))),
		};
		Box::pin(ready(Ok(Ok(operation))))
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

	fn hash_and_length(&self, ex: &StfTrustedOperation) -> (ExtrinsicHash<Self>, usize) {
		debug!("[Pool] creating hash of {:?}", ex);
		ex.using_encoded(|x| (<<Block::Header as HeaderT>::Hashing as HashT>::hash(x), x.len()))
	}

	fn block_body(&self, _id: &BlockId<Self::Block>) -> Self::BodyFuture {
		ready(Ok(None))
	}
}
