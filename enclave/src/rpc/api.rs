// This file is part of Substrate.

// Copyright (C) 2018-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Chain api required for the transaction pool.
extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use codec::Encode;
use jsonrpc_core::futures::future::{ready, Future, Ready};
use sgx_tstd::{marker::PhantomData, pin::Pin};

use sp_runtime::{
    generic::BlockId,
    traits::{Block as BlockT, Hash as HashT, Header as HeaderT},
    transaction_validity::{TransactionSource, TransactionValidity, ValidTransaction},
};

use crate::top_pool::pool::{BlockHash, ChainApi, ExtrinsicHash, NumberFor};

use substratee_stf::TrustedCallSigned;

use crate::rpc::error;

/// The transaction pool logic for full client.
pub struct FillerChainApi<Block> {
    _marker: PhantomData<Block>,
}

impl<Block> FillerChainApi<Block> {
    /// Create new transaction pool logic.
    pub fn new() -> Self {
        FillerChainApi {
            _marker: Default::default(),
        }
    }
}

impl<Block> ChainApi for FillerChainApi<Block>
where
    Block: BlockT,
{
    type Block = Block;
    type Error = error::Error;
    type ValidationFuture =
        Pin<Box<dyn Future<Output = error::Result<TransactionValidity>> + Send>>;
    type BodyFuture = Ready<error::Result<Option<Vec<TrustedCallSigned>>>>;

    fn block_body(&self, _id: &BlockId<Self::Block>) -> Self::BodyFuture {
        ready(Ok(None))
    }

    fn validate_transaction(
        &self,
        _at: &BlockId<Self::Block>,
        _source: TransactionSource,
        uxt: TrustedCallSigned,
    ) -> Self::ValidationFuture {
        let transaction = ValidTransaction {
            priority: uxt.nonce.into(),
            requires: vec![],
            provides: vec![vec![uxt.nonce as u8]],
            longevity: 3,
            propagate: true,
        };
        Box::pin(ready(Ok(Ok(transaction))))
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
        _at: &BlockId<Self::Block>,
    ) -> error::Result<Option<BlockHash<Self>>> {
        Ok(None)
    }

    fn hash_and_length(&self, ex: &TrustedCallSigned) -> (ExtrinsicHash<Self>, usize) {
        /*let encoded = ex.encode();
        let len = encoded.len();
        (Hashing::hash(&encoded) as Hash, len)*/
        ex.using_encoded(|x| {
            (
                <<Block::Header as HeaderT>::Hashing as HashT>::hash(x),
                x.len(),
            )
        })
    }
}
