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

//! Chain api required for the operation pool.
extern crate alloc;
use alloc::{boxed::Box, vec::Vec};
use log::*;

use codec::{Encode, Decode};
use jsonrpc_core::futures::future::{ready, Future, Ready};
use std::{marker::PhantomData, pin::Pin};

use sp_runtime::{
    generic::BlockId,
    traits::{Block as BlockT, Hash as HashT, Header as HeaderT},
    transaction_validity::{
        TransactionValidity, TransactionValidityError, UnknownTransaction,
        InvalidTransaction, ValidTransaction,
    },
};

use crate::top_pool::pool::{ChainApi, ExtrinsicHash, NumberFor};
use crate::top_pool::primitives::TrustedOperationSource;
use crate::state;

use substratee_stf::{Getter, TrustedOperation as StfTrustedOperation, AccountId,
     Index, ShardIdentifier, Stf};
use substratee_worker_primitives::BlockHash as SidechainBlockHash;

use crate::rpc::error;

/// Future that resolves to account nonce.
pub type Result<T> = core::result::Result<T, ()>;

/// The operation pool logic for full client.
pub struct SideChainApi<Block> {
    _marker: PhantomData<Block>,
}

impl<Block> SideChainApi<Block> {
    /// Create new operation pool logic.
    pub fn new() -> Self {
        SideChainApi {
            _marker: Default::default(),
        }
    }
}

fn expected_nonce(shard: ShardIdentifier, account: &AccountId) -> Result<Index> {
    if !state::exists(&shard) {
        //FIXME: Should this be an error? -> Issue error handling
        error!("Shard does not exists");
        return Ok(0 as Index)
    }

    let mut state = match state::load(&shard) {
        Ok(s) => s,
        Err(e) => {
            //FIXME: Should this be an error? -> Issue error handling
            error!("State could not be loaded");
            return Err(())
        }
    };

    let nonce: Index = if let Some(nonce_encoded) = Stf::account_nonce(&mut state, account.clone()) {
        match Decode::decode(&mut nonce_encoded.as_slice()) {
            Ok(index) => index,
            Err(e) => {
                error!("Could not decode index");
                return Err(())
            },
        }
    } else {
        0 as Index
    };

    Ok(nonce)
}

impl<Block> ChainApi for SideChainApi<Block>
where
    Block: BlockT,
{
    type Block = Block;
    type Error = error::Error;
    type ValidationFuture =
        Pin<Box<dyn Future<Output = error::Result<TransactionValidity>> + Send>>;
    type BodyFuture = Ready<error::Result<Option<Vec<StfTrustedOperation>>>>;

    fn block_body(&self, _id: &BlockId<Self::Block>) -> Self::BodyFuture {
        ready(Ok(None))
    }

    fn validate_transaction(
        &self,
        _source: TrustedOperationSource,
        uxt: StfTrustedOperation,
        shard: ShardIdentifier,
    ) -> Self::ValidationFuture {
        let operation = match uxt {
            StfTrustedOperation::direct_call(signed_call) => {
                let nonce = signed_call.nonce;
                let from = signed_call.call.account();

                let expected_nonce = match expected_nonce(shard, &from) {
                    Ok(nonce) => nonce,
                    Err(_) => return Box::pin(ready(Ok(Err(TransactionValidityError::Unknown(
                        UnknownTransaction::CannotLookup,
                    ))))),
                };
                if nonce < expected_nonce {
                    return Box::pin(ready(Ok(Err(TransactionValidityError::Invalid(
                        InvalidTransaction::Stale
                    )))))
                }
                if nonce > expected_nonce + 64 {
                    return Box::pin(ready(Ok(Err(TransactionValidityError::Invalid(
                        InvalidTransaction::Future
                    )))))
                }
                let encode = |from: &AccountId, nonce: Index| (from, nonce).encode();
                let requires = if nonce != expected_nonce && nonce > 0 {
                    vec![encode(&from, nonce - 1)]
                } else {
                    vec![]
                };

                let provides = vec![encode(&from, nonce)];

                ValidTransaction {
                    priority: 1 << 20,
                    requires: requires,
                    provides: provides,
                    longevity: 64,
                    propagate: true,
                }
            },
            StfTrustedOperation::get(getter) => match getter {
                Getter::public(_) => {
                    return Box::pin(ready(Ok(Err(TransactionValidityError::Unknown(
                        UnknownTransaction::CannotLookup,
                    )))))
                }
                Getter::trusted(trusted_getter) => ValidTransaction {
                    priority: 1 << 20,
                    requires: vec![],
                    provides: vec![trusted_getter.signature.encode()],
                    longevity: 64,
                    propagate: true,
                },
            },
            _ => {
                return Box::pin(ready(Ok(Err(TransactionValidityError::Unknown(
                    UnknownTransaction::CannotLookup,
                )))))
            }
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
        ex.using_encoded(|x| {
            (
                <<Block::Header as HeaderT>::Hashing as HashT>::hash(x),
                x.len(),
            )
        })
    }
}


pub mod tests {
	use super::*;
    use substratee_stf::TrustedCall;
    use sp_core::{ed25519 as spEd25519, Pair};
    use jsonrpc_core::futures::executor;
    use chain_relay::Block;

	pub fn test_validate_transaction_works() {
		// given
		let api = SideChainApi::<Block>::new();
	    let shard = ShardIdentifier::default();
		// ensure state starts empty
		state::init_shard(&shard).unwrap();
		Stf::init_state();

		// create account
		let account_pair = spEd25519::Pair::from_seed(b"12345678901234567890123456789012");
        let account = account_pair.public();

		let source = TrustedOperationSource::External;

		// create top call function
		let new_top_call = |nonce: Index| {
			let mrenclave = [0u8; 32];
			let call = TrustedCall::balance_set_balance(
				account.into(),
				account.into(),
				42,
				42,
			);
			let signed_call = call.sign(&account_pair.clone().into(), nonce, &mrenclave, &shard);
			signed_call.into_trusted_operation(true)
		};
		let top0 = new_top_call(0);
        let top1 = new_top_call(1);

		// when
        let validation_result = async { api
            .validate_transaction(source, top0.clone(), shard)
            .await };
        let valid_transaction: ValidTransaction = executor::block_on(validation_result).unwrap().unwrap();

		// then
		assert_eq!(valid_transaction.priority, 1<<20);
        //assert_eq!(valid_transaction.requires, vec![]);
        assert_eq!(valid_transaction.provides, vec![(&account,0 as Index).encode()]);
        assert_eq!(valid_transaction.longevity, 64);
        assert!(valid_transaction.propagate);
	}
}
