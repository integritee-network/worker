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
use alloc::{vec::Vec};
use codec::{self, Decode, Encode};
use sp_runtime::{
	generic::BlockId,
};
use sp_core::{hexdisplay::HexDisplay};


use log::*;

use std::sync::Arc;
use core::iter::Iterator;

use crate::top_pool::{
    primitives::{InPoolOperation, TrustedOperationPool, TrustedOperationSource},
};
use jsonrpc_core::{Error as RpcError, ErrorCode};

use crate::rsa3072;
use crate::state;

use substratee_stf::{
    AccountId, ShardIdentifier, Stf, TrustedCall, Index,
};


use crate::ed25519;
use crate::rpc;


use sp_core::{crypto::Pair};


use chain_relay::{Block};

use jsonrpc_core::futures::executor;
use sp_core::ed25519 as spEd25519;

use rpc::{api::SideChainApi, basic_pool::BasicPool};

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

		let nonce: Index = Stf::account_nonce(&mut state, &account);
		Ok(adjust_nonce(self.pool.clone(), account, nonce, shard))
	}
}


/// Adjust account nonce from state, so that tx with the nonce will be
/// placed after all ready txpool transactions.
fn adjust_nonce<P>(
	pool: Arc<&P>,
	account: AccountId,
	nonce: Index,
    shard: ShardIdentifier,
) -> Index where
	P: TrustedOperationPool,
{
	debug!("State nonce: {}", nonce);
	// Now we need to query the transaction pool
	// and find transactions originating from the same sender.
	//
	// Since extrinsics are opaque to us, we look for them using
	// `provides` tag. And increment the nonce if we find a transaction
	// that matches the current one.
	let mut current_nonce: Index = nonce.clone();
	let mut current_tag = (account.clone(), nonce).encode();
	for tx in pool.ready(shard) {
		debug!(
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

pub mod tests {
	use super::*;

	pub fn test_should_return_next_nonce_for_some_account() {
		// given
		// create top pool
		let api: Arc<SideChainApi<Block>> = Arc::new(SideChainApi::new());
		let tx_pool = BasicPool::create(Default::default(), api);

		let shard = ShardIdentifier::default();
		// ensure state starts empty
		state::init_shard(&shard).unwrap();
		Stf::init_state();

		// create account
		let signer_account = spEd25519::Pair::from_seed(b"12345678901234567890123456789012");
		let account = signer_account.public();

		let source = TrustedOperationSource::External;

		// encrypt account
		let rsa_pubkey = rsa3072::unseal_pubkey().unwrap();
		let mut encrypted_account: Vec<u8> = Vec::new();
			rsa_pubkey
				.encrypt_buffer(&account.encode(), &mut encrypted_account)
				.unwrap();

		// create top call function
		let new_top_call = |nonce: Index| {
			let mrenclave = [0u8; 32];
			let call = TrustedCall::balance_set_balance(
				account.into(),
				account.into(),
				42,
				42,
			);
			let signed_call = call.sign(&signer_account.clone().into(), nonce, &mrenclave, &shard);
			signed_call.into_trusted_operation(true)
		};
		// Populate the pool
		let top0 = new_top_call(0);
		let hash1 = executor::block_on(tx_pool.submit_one(&BlockId::number(0), source, top0, shard)).unwrap();
		let top1 = new_top_call(1);
		let hash2 = executor::block_on(tx_pool.submit_one(&BlockId::number(0), source, top1, shard)).unwrap();
		// future doesnt count
		let top3 = new_top_call(3);
		let _hash3 = executor::block_on(tx_pool.submit_one(&BlockId::number(0), source, top3, shard)).unwrap();
		assert_eq!(
			tx_pool.ready(shard)
				.map(|v| v.hash)
				.collect::<Vec<_>>(),
			vec![hash1, hash2]
		);

		let system = FullSystem::new(Arc::new(&tx_pool));

		// when
		let nonce = system.nonce(encrypted_account, shard);

		// then
		assert_eq!(nonce.unwrap(), 2);

		// clean up
		state::remove_shard_dir(&shard);
	}
}