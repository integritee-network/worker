use sgx_tstd::collections::HashSet;
use sgx_tstd::sync::SgxMutex as Mutex;
use sp_runtime::{
generic::BlockId,
traits::{Block as BlockT, Hash},
transaction_validity::{TransactionValidity, TransactionSource, ValidTransaction},
};
use primitive_types::H256;
use substrate_test_runtime::{Block, Extrinsic, Hashing};
use jsonrpc_core::futures::future;

pub extern crate alloc;
use alloc::{
  vec::Vec,
  sync::Arc,
};

use crate::transaction_pool::{
  pool::{ExtrinsicFor, NumberFor, ChainApi, BlockHash},
  error as txError,
};

use jsonrpc_core::*;
use codec::{Encode};


#[derive(Default)]
pub struct TestApi {
	delay: Arc<Mutex<Option<std::sync::mpsc::Receiver<()>>>>,
	invalidate: Arc<Mutex<HashSet<H256>>>,
	clear_requirements: Arc<Mutex<HashSet<H256>>>,
	add_requirements: Arc<Mutex<HashSet<H256>>>,
}

impl ChainApi for TestApi {
	type Block = Block;
	type Error = txError::Error;
	type ValidationFuture = future::Ready<txError::Result<TransactionValidity>>;
	type BodyFuture = future::Ready<txError::Result<Option<Vec<Extrinsic>>>>;

	/// Verify extrinsic at given block.
	fn validate_transaction(
		&self,
		at: &BlockId<Self::Block>,
		_source: TransactionSource,
		uxt: ExtrinsicFor<Self>,
	) -> Self::ValidationFuture {
		let transaction = ValidTransaction {
			priority: 4,
			requires: vec![] ,
			provides:  vec![],
			longevity: 3,
			propagate: true,
		};
		future::ready(Ok(Ok(transaction)))
	}

	/// Returns a block number given the block id.
	fn block_id_to_number(
		&self,
		at: &BlockId<Self::Block>,
	) -> core::result::Result<Option<NumberFor<Self>>, Self::Error> {
		Ok(match at {
			BlockId::Number(num) => Some(*num),
			BlockId::Hash(_) => None,
		})
	}

	/// Returns a block hash given the block id.
	fn block_id_to_hash(
		&self,
		at: &BlockId<Self::Block>,
	) -> core::result::Result<Option<<Self::Block as BlockT>::Hash>, Self::Error> {
		Ok(None)
	}

	/// Hash the extrinsic.
	fn hash_and_length(&self, uxt: &ExtrinsicFor<Self>) -> (BlockHash<Self>, usize) {
		let encoded = uxt.encode();
		let len = encoded.len();
		(Hashing::hash(&encoded), len)
	}

	fn block_body(&self, _id: &BlockId<Self::Block>) -> Self::BodyFuture {
		futures::future::ready(Ok(None))
	}
}
  

