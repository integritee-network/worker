// This file is part of Substrate.

// Copyright (C) 2017-2020 Parity Technologies (UK) Ltd.
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

//! Substrate block-author/full-node API.
pub extern crate alloc;
use alloc::{
  vec::Vec,
  boxed::Box,
};

use sgx_tstd::{sync::Arc};

use core::iter::Iterator;
use jsonrpc_core::futures::future::{ready, TryFutureExt};
//use jsonrpc_pubsub::{typed::Subscriber, SubscriptionId, manager::SubscriptionManager};
use codec::{Encode, Decode};
//use sp_keystore::{SyncCryptoStorePtr, SyncCryptoStore};
use sp_runtime::generic;
//use sp_session::SessionKeys;
use sp_runtime::transaction_validity::{
	TransactionSource,	
};

use substratee_stf::{
    Getter, ShardIdentifier, TrustedCallSigned, TrustedOperation,
};

use crate::rpc::error::{FutureResult, Result};
use crate::rpc::error::Error as StateRpcError;
use crate::transaction_pool::{
  primitives::{TransactionPool, InPoolTransaction, TxHash, BlockHash},
	error::IntoPoolError, error::Error as PoolError,
	pool::Pool,
};
use jsonrpc_core::Error as RpcError;
pub mod client_error;
use client_error::Error as ClientError;
pub mod hash;
use hash::*;
use sp_core::H256 as H256;


/// Substrate authoring RPC API
pub trait AuthorApi<Hash, BlockHash> {
	/// RPC metadata
	//type Metadata;

	/// Submit hex-encoded extrinsic for inclusion in block.
	fn submit_extrinsic(&self, extrinsic: Vec<u8>) -> FutureResult<Hash, RpcError>;
	//fn submit_extrinsic(&self, extrinsic: Vec<u8>) ->Pin<Box<dyn jsonrpc_core::futures::Future<Output=core::result::Result<H256, RpcError>> + Send>>;
	
	/*/// Insert a key into the keystore.
	fn insert_key(
		&self,
		key_type: String,
		suri: String,
		public: <Vec<u8>,
	) -> Result<()>;

	/// Generate new session keys and returns the corresponding public keys.
	fn rotate_keys(&self) -> Result<<Vec<u8>>;

	/// Checks if the keystore has private keys for the given session public keys.
	///
	/// `session_keys` is the SCALE encoded session keys object from the runtime.
	///
	/// Returns `true` iff all private keys could be found.
	fn has_session_keys(&self, session_keys: <Vec<u8>) -> Result<bool>;

	/// Checks if the keystore has private keys for the given public key and key type.
	///
	/// Returns `true` if a private key could be found.
	fn has_key(&self, public_key: <Vec<u8>, key_type: String) -> Result<bool>;*/

	/// Returns all pending extrinsics, potentially grouped by sender.
	fn pending_extrinsics(&self) -> Result<Vec<Vec<u8>>>;

	/// Remove given extrinsic from the pool and temporarily ban it to prevent reimporting.
	fn remove_extrinsic(&self,
		bytes_or_hash: Vec<hash::ExtrinsicOrHash<Hash>>
	) -> Result<Vec<Hash>>;

	/*/// Submit an extrinsic to watch.
	///
	/// See [`TransactionStatus`](sp_transaction_pool::TransactionStatus) for details on transaction
	/// life cycle.
	#[pubsub(
		subscription = "author_extrinsicUpdate",
		subscribe,
		name = "author_submitAndWatchExtrinsic"
	)]
	fn watch_extrinsic(&self,
		metadata: Self::Metadata,
		subscriber: Subscriber<TransactionStatus<Hash, BlockHash>>,
		bytes: <Vec<u8>
	);

	/// Unsubscribe from extrinsic watching.
	#[pubsub(
		subscription = "author_extrinsicUpdate",
		unsubscribe,
		name = "author_unwatchExtrinsic"
	)]
	fn unwatch_extrinsic(&self,
		metadata: Option<Self::Metadata>,
		id: SubscriptionId
	) -> Result<bool>;*/
}

/// Authoring API
//pub struct Author<P, Client> {
pub struct Author<P> {
	/// Substrate client
	//client: Arc<Client>,
	/// Transactions pool
	pool: Arc<P>,
	/*/// Subscriptions manager
	subscriptions: SubscriptionManager,*/
	/*/// The key store.
	keystore: SyncCryptoStorePtr,*/
	/*/// Whether to deny unsafe calls
	deny_unsafe: DenyUnsafe,*/
}

//impl<P, Client> Author<P, Client> {
impl<P> Author<P> {
	/// Create new instance of Authoring API.
	pub fn new(
		//client: Arc<Client>,
		pool: Arc<P>,
		//subscriptions: SubscriptionManager,
		//keystore: SyncCryptoStorePtr,
		//deny_unsafe: DenyUnsafe,
	) -> Self {
		Author {
			//client,
			pool,
			//subscriptions,
			//keystore,
			//deny_unsafe,
		}
	}
}

/// Currently we treat all RPC transactions as externals.
///
/// Possibly in the future we could allow opt-in for special treatment
/// of such transactions, so that the block authors can inject
/// some unique transactions via RPC and have them included in the pool.
const TX_SOURCE: TransactionSource = TransactionSource::External;

//impl<P, Client> AuthorApi<TxHash<P>, BlockHash<P>> for Author<P, Client>
impl<P> AuthorApi<TxHash<P>, BlockHash<P>> for Author<P>
	where
		P: TransactionPool + Sync + Send + 'static,
		//Client: Send + Sync + 'static,
		//Client::Api: SessionKeys<P::Block, Error = ClientError>,
{
	//type Metadata = crate::Metadata;

	/*fn insert_key(
		&self,
		key_type: String,
		suri: String,
		public: <Vec<u8>,
	) -> Result<()> {
		self.deny_unsafe.check_if_safe()?;

		let key_type = key_type.as_str().try_into().map_err(|_| ClientError::BadKeyType)?;
		SyncCryptoStore::insert_unknown(&*self.keystore, key_type, &suri, &public[..])
			.map_err(|_| ClientError::KeyStoreUnavailable)?;
		Ok(())
	}

	fn rotate_keys(&self) -> Result<<Vec<u8>> {
		self.deny_unsafe.check_if_safe()?;

		let best_block_hash = self.client.info().best_hash;
		self.client.runtime_api().generate_session_keys(
			&generic::BlockId::Hash(best_block_hash),
			None,
		).map(Into::into).map_err(|e| ClientError::Client(Box::new(e)))
	}

	fn has_session_keys(&self, session_keys: <Vec<u8>) -> Result<bool> {
		self.deny_unsafe.check_if_safe()?;

		let best_block_hash = self.client.info().best_hash;
		let keys = self.client.runtime_api().decode_session_keys(
			&generic::BlockId::Hash(best_block_hash),
			session_keys.to_vec(),
		).map_err(|e| ClientError::Client(Box::new(e)))?
			.ok_or_else(|| ClientError::InvalidSessionKeys)?;

		Ok(SyncCryptoStore::has_keys(&*self.keystore, &keys))
	}

	fn has_key(&self, public_key: <Vec<u8>, key_type: String) -> Result<bool> {
		self.deny_unsafe.check_if_safe()?;

		let key_type = key_type.as_str().try_into().map_err(|_| ClientError::BadKeyType)?;
		Ok(SyncCryptoStore::has_keys(&*self.keystore, &[(public_key.to_vec(), key_type)]))
	}*/

	/// Submit hex-encoded extrinsic for inclusion in block.	
	/*fn submit_extrinsic(&self, ext: Vec<u8>) ->  Pin<Box<dyn jsonrpc_core::futures::Future<Output=core::result::Result<H256, RpcError>> + Send>>
	{
		return Box::pin(ready(Ok(H256::from_slice(&ext[..]))));
	}*/
	
	fn submit_extrinsic(&self, ext: Vec<u8>) -> FutureResult<TxHash<P>, RpcError>
	{	
		let xt = match Decode::decode(&mut &ext[..]) {
			Ok(xt) => xt,
			Err(_) => return Box::pin(ready(Err(ClientError::BadFormat.into()))),
		};
		//let best_block_hash = self.client.info().best_hash;
		// dummy block hash
		let best_block_hash = Default::default();
		Box::pin(self.pool
			.submit_one(&generic::BlockId::hash(best_block_hash), TX_SOURCE, xt)
			.map_err(|e| StateRpcError::PoolError(e.into_pool_error()
				.map(Into::into)
				.unwrap_or_else(|_e| PoolError::Verification)).into()
		))
	}

	fn pending_extrinsics(&self) -> Result<Vec<Vec<u8>>> {
		Ok(self.pool.ready().map(|tx| tx.data().encode().into()).collect())
	}

	fn remove_extrinsic(
		&self,
		bytes_or_hash: Vec<hash::ExtrinsicOrHash<TxHash<P>>>,
	) -> Result<Vec<TxHash<P>>> {
		let hashes = bytes_or_hash.into_iter()
			.map(|x| match x {
				hash::ExtrinsicOrHash::Hash(h) => Ok(h),
				hash::ExtrinsicOrHash::Extrinsic(bytes) => {
					let xt = Decode::decode(&mut &bytes[..]).unwrap();
					Ok(self.pool.hash_of(&xt))
				},
			})
			.collect::<Result<Vec<_>>>()?;

		Ok(
			self.pool
				.remove_invalid(&hashes)
				.into_iter()
				.map(|tx| tx.hash().clone())
				.collect()
		)
	}

/*	fn watch_extrinsic(&self,
		_metadata: Self::Metadata,
		subscriber: Subscriber<TransactionStatus<TxHash<P>, BlockHash<P>>>,
		xt: <Vec<u8>,
	) {
		let submit = || -> Result<_> {
			let best_block_hash = self.client.info().best_hash;
			let dxt = TrustedCallSigned::decode(&mut &xt[..])
				.map_err(error::Error::from)?;
			Ok(
				self.pool
					.submit_and_watch(&generic::BlockId::hash(best_block_hash), TX_SOURCE, dxt)
					.map_err(|e| e.into_pool_error()
						.map(error::Error::from)
						.unwrap_or_else(|e| error::Error::Verification(Box::new(e)).into())
					)
			)
		};

		let subscriptions = self.subscriptions.clone();
		let future = ready(submit())
			.and_then(|res| res)
			// convert the watcher into a `Stream`
			.map(|res| res.map(|stream| stream.map(|v| Ok::<_, ()>(Ok(v)))))
			// now handle the import result,
			// start a new subscrition
			.map(move |result| match result {
				Ok(watcher) => {
					subscriptions.add(subscriber, move |sink| {
						sink
							.sink_map_err(|e| log::debug!("Subscription sink failed: {:?}", e))
							.send_all(Compat::new(watcher))
							.map(|_| ())
					});
				},
				Err(err) => {
					warn!("Failed to submit extrinsic: {}", err);
					// reject the subscriber (ignore errors - we don't care if subscriber is no longer there).
					let _ = subscriber.reject(err.into());
				},
			});

		let res = self.subscriptions.executor()
			.execute(Box::new(Compat::new(future.map(|_| Ok(())))));
		if res.is_err() {
			warn!("Error spawning subscription RPC task.");
		}
	}

	fn unwatch_extrinsic(&self, _metadata: Option<Self::Metadata>, id: SubscriptionId) -> Result<bool> {
		Ok(self.subscriptions.cancel(id))
	}*/
}
