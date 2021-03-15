// This file is part of Substrate.

// Copyright (C) 2019-2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! System FRAME specific RPC methods.

pub extern crate alloc;
use alloc::{boxed::Box, vec::Vec};
use core::pin::Pin;

use codec::{self, Codec, Decode, Encode};
use sp_runtime::{
	generic::BlockId,
	traits,
};
use sp_core::{hexdisplay::HexDisplay, Bytes};


use log::*;

use std::sync::Arc;
use core::iter::Iterator;
use jsonrpc_core::futures::future::{ready, TryFutureExt, Future};
use sp_runtime::generic;

use crate::rpc::error::Error as StateRpcError;
use crate::top_pool::{
    error::Error as PoolError,
    error::IntoPoolError,
    primitives::{
        BlockHash, InPoolOperation, TrustedOperationPool, TrustedOperationSource, TxHash,
    },
};
use jsonrpc_core::{Error as RpcError, ErrorCode};

use crate::rsa3072;
use crate::state;

use substratee_stf::{
    AccountId, Getter, ShardIdentifier, Stf, TrustedCall, TrustedCallSigned, TrustedGetterSigned, Index,
};

/// Future that resolves to account nonce.
pub type Result<T> = core::result::Result<T, RpcError>;

/// System RPC methods.
pub trait SystemApi {
	/// Returns the next valid index (aka nonce) for given account.
	///
	/// This method takes into consideration all pending transactions
	/// currently in the pool and if no transactions are found in the pool
	/// it fallbacks to query the index from the runtime (aka. state nonce).
	fn nonce(&self, encrypted_account: Vec<u8>, shard: ShardIdentifier) -> Result<Index>;
}

/// Error type of this RPC api.
pub enum Error {
	/// The transaction was not decodable.
	DecodeError,
	/// The call to state failed.
	StateError,
}

impl From<Error> for i64 {
	fn from(e: Error) -> i64 {
		match e {
			Error::StateError => 1,
			Error::DecodeError => 2,
		}
	}
}

/// An implementation of System-specific RPC methods on full client.
pub struct FullSystem<P> {
	pool: Arc<P>,
}

impl<P> FullSystem<P> {
	/// Create new `FullSystem` given client and transaction pool.
	pub fn new(pool: Arc<P>) -> Self {
		FullSystem {
			pool,
		}
	}
}

impl<P> SystemApi for FullSystem<&P>
where
	P: TrustedOperationPool + 'static,
{
	fn nonce(&self, encrypted_account: Vec<u8>, shard: ShardIdentifier) -> Result<Index> {
		if !state::exists(&shard) {
			//FIXME: Should this be an error? -> Issue error handling
			error!("Shard does not exists");
			return Ok(0 as Index)
		}
		// decrypt account
        let rsa_keypair = rsa3072::unseal_pair().unwrap();
        let account_vec: Vec<u8> = match rsa3072::decrypt(&encrypted_account.as_slice(), &rsa_keypair) {
            Ok(acc) => acc,
            Err(e) => return Err(RpcError {
				code: ErrorCode::ServerError(Error::DecodeError.into()),
				message: "Unable to query nonce.".into(),
				data: Some(format!("{:?}", e).into())
			})
        };
        // decode account
        let account = match AccountId::decode(&mut account_vec.as_slice()) {
            Ok(acc) => acc,
            Err(e) => return Err(RpcError {
				code: ErrorCode::ServerError(Error::DecodeError.into()),
				message: "Unable to query nonce.".into(),
				data: Some(format!("{:?}", e).into())
			})
        };

		let mut state = match state::load(&shard) {
			Ok(s) => s,
			Err(e) => {
				//FIXME: Should this be an error? -> Issue error handling
				error!("Shard could not be loaded");
				return Err(RpcError {
					code: ErrorCode::ServerError(Error::StateError.into()),
					message: "Unable to query nonce of current state.".into(),
					data: Some(format!("{:?}", e).into())
				})
			}
		};

		let nonce: Index = if let Some(nonce_encoded) = Stf::account_nonce(&mut state, account.clone()) {
			match Decode::decode(&mut nonce_encoded.as_slice()) {
				Ok(index) => index,
				Err(e) => {
					error!("Could not decode index");
					return Err(RpcError {
						code: ErrorCode::ServerError(Error::DecodeError.into()),
						message: "Unable to query nonce.".into(),
						data: Some(format!("{:?}", e).into())
					})
				},
			}
		} else {
			0 as Index
		};

		Ok(adjust_nonce(*self.pool, account, nonce, shard))
	}
}


/// Adjust account nonce from state, so that tx with the nonce will be
/// placed after all ready txpool transactions.
fn adjust_nonce<P>(
	pool: &P,
	account: AccountId,
	nonce: Index,
    shard: ShardIdentifier,
) -> Index where
	P: TrustedOperationPool,
{
	log::debug!(target: "rpc", "State nonce for {:?}: {}", account, nonce);
	// Now we need to query the transaction pool
	// and find transactions originating from the same sender.
	//
	// Since extrinsics are opaque to us, we look for them using
	// `provides` tag. And increment the nonce if we find a transaction
	// that matches the current one.
	let mut current_nonce: Index = nonce.clone();
	let mut current_tag = (account.clone(), nonce).encode();
	for tx in pool.ready(shard) {
		log::debug!(
			target: "rpc",
			"Current nonce to {}, checking {} vs {:?}",
			current_nonce,
			HexDisplay::from(&current_tag),
			tx.provides().iter().map(|x| format!("{}", HexDisplay::from(x))).collect::<Vec<_>>(),
		);
		// since transactions in `ready()` need to be ordered by nonce
		// it's fine to continue with current iterator.
		if tx.provides().get(0) == Some(&current_tag) {
			current_nonce += 1;
			current_tag = (account.clone(), current_nonce.clone()).encode();
		}
	}

	current_nonce
}

/* #[cfg(test)]
mod tests {
	use super::*;

	use futures::executor::block_on;
	use substrate_test_runtime_client::{runtime::Transfer, AccountKeyring};
	use sc_transaction_pool::BasicPool;
	use sp_runtime::{ApplyExtrinsicResult, transaction_validity::{TransactionValidityError, InvalidTransaction}};

	#[test]
	fn should_return_next_nonce_for_some_account() {
		sp_tracing::try_init_simple();

		// given
		let client = Arc::new(substrate_test_runtime_client::new());
		let spawner = sp_core::testing::TaskExecutor::new();
		let pool = BasicPool::new_full(
			Default::default(),
			true.into(),
			None,
			spawner,
			client.clone(),
		);

		let source = sp_runtime::transaction_validity::TransactionSource::External;
		let new_transaction = |nonce: u64| {
			let t = Transfer {
				from: AccountKeyring::Alice.into(),
				to: AccountKeyring::Bob.into(),
				amount: 5,
				nonce,
			};
			t.into_signed_tx()
		};
		// Populate the pool
		let ext0 = new_transaction(0);
		block_on(pool.submit_one(&BlockId::number(0), source, ext0)).unwrap();
		let ext1 = new_transaction(1);
		block_on(pool.submit_one(&BlockId::number(0), source, ext1)).unwrap();

		let accounts = FullSystem::new(client, pool, DenyUnsafe::Yes);

		// when
		let nonce = accounts.nonce(AccountKeyring::Alice.into());

		// then
		assert_eq!(nonce.wait().unwrap(), 2);
	}

	#[test]
	fn dry_run_should_deny_unsafe() {
		sp_tracing::try_init_simple();

		// given
		let client = Arc::new(substrate_test_runtime_client::new());
		let spawner = sp_core::testing::TaskExecutor::new();
		let pool = BasicPool::new_full(
			Default::default(),
			true.into(),
			None,
			spawner,
			client.clone(),
		);

		let accounts = FullSystem::new(client, pool, DenyUnsafe::Yes);

		// when
		let res = accounts.dry_run(vec![].into(), None);

		// then
		assert_eq!(res.wait(), Err(RpcError::method_not_found()));
	}

	#[test]
	fn dry_run_should_work() {
		sp_tracing::try_init_simple();

		// given
		let client = Arc::new(substrate_test_runtime_client::new());
		let spawner = sp_core::testing::TaskExecutor::new();
		let pool = BasicPool::new_full(
			Default::default(),
			true.into(),
			None,
			spawner,
			client.clone(),
		);

		let accounts = FullSystem::new(client, pool, DenyUnsafe::No);

		let tx = Transfer {
			from: AccountKeyring::Alice.into(),
			to: AccountKeyring::Bob.into(),
			amount: 5,
			nonce: 0,
		}.into_signed_tx();

		// when
		let res = accounts.dry_run(tx.encode().into(), None);

		// then
		let bytes = res.wait().unwrap().0;
		let apply_res: ApplyExtrinsicResult = Decode::decode(&mut bytes.as_slice()).unwrap();
		assert_eq!(apply_res, Ok(Ok(())));
	}

	#[test]
	fn dry_run_should_indicate_error() {
		sp_tracing::try_init_simple();

		// given
		let client = Arc::new(substrate_test_runtime_client::new());
		let spawner = sp_core::testing::TaskExecutor::new();
		let pool = BasicPool::new_full(
			Default::default(),
			true.into(),
			None,
			spawner,
			client.clone(),
		);

		let accounts = FullSystem::new(client, pool, DenyUnsafe::No);

		let tx = Transfer {
			from: AccountKeyring::Alice.into(),
			to: AccountKeyring::Bob.into(),
			amount: 5,
			nonce: 100,
		}.into_signed_tx();

		// when
		let res = accounts.dry_run(tx.encode().into(), None);

		// then
		let bytes = res.wait().unwrap().0;
		let apply_res: ApplyExtrinsicResult = Decode::decode(&mut bytes.as_slice()).unwrap();
		assert_eq!(apply_res, Err(TransactionValidityError::Invalid(InvalidTransaction::Stale)));
	}
} */
