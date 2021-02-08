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
use alloc::{boxed::Box, vec::Vec};

use sgx_tstd::sync::Arc;

use codec::{Decode, Encode};
use core::iter::Iterator;
use jsonrpc_core::futures::future::{ready, TryFutureExt};
use sp_runtime::generic;
use sp_runtime::transaction_validity::TransactionSource;

use substratee_stf::{ShardIdentifier, TrustedCallSigned};

use crate::rpc::error::Error as StateRpcError;
use crate::rpc::error::{FutureResult, Result};
use crate::transaction_pool::{
    error::Error as PoolError,
    error::IntoPoolError,
    primitives::{BlockHash, InPoolTransaction, TransactionPool, TxHash},
};
use jsonrpc_core::Error as RpcError;
pub mod client_error;
use client_error::Error as ClientError;
pub mod hash;

use crate::rsa3072;
use crate::state;

/// Substrate authoring RPC API
pub trait AuthorApi<Hash, BlockHash> {
    /// RPC metadata
    //type Metadata;

    /// Submit hex-encoded extrinsic for inclusion in block.
    fn submit_call(
        &self,
        extrinsic: Vec<u8>,
        shard: ShardIdentifier,
    ) -> FutureResult<Hash, RpcError>;

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

    /// Returns all pending calls, potentially grouped by sender.
    fn pending_calls(&self, shard: ShardIdentifier) -> Result<Vec<Vec<u8>>>;

    fn get_shards(&self) -> Vec<ShardIdentifier>;

    /// Remove given call from the pool and temporarily ban it to prevent reimporting.
    fn remove_call(
        &self,
        bytes_or_hash: Vec<hash::TrustedCallOrHash<Hash>>,
        shard: ShardIdentifier,
        inblock: bool,
    ) -> Result<Vec<Hash>>;

    /// Submit an extrinsic to watch.
    ///
    /// See [`TransactionStatus`](sp_transaction_pool::TransactionStatus) for details on transaction
    /// life cycle.
    /* 	fn watch_call(&self,
        //metadata: Self::Metadata,
        //subscriber: Subscriber<TransactionStatus<Hash, BlockHash>>,
        bytes: Vec<u8>,
        shard: ShardIdentifier,
    ); */

    fn watch_call(&self, ext: Vec<u8>, shard: ShardIdentifier) -> FutureResult<Hash, RpcError>;

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
impl<P> AuthorApi<TxHash<P>, BlockHash<P>> for Author<&P>
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

    fn submit_call(
        &self,
        ext: Vec<u8>,
        shard: ShardIdentifier,
    ) -> FutureResult<TxHash<P>, RpcError> {
        // decrypt call
        let rsa_keypair = rsa3072::unseal_pair().unwrap();
        let request_vec: Vec<u8> = match rsa3072::decrypt(&ext.as_slice(), &rsa_keypair) {
            Ok(req) => req,
            Err(_) => return Box::pin(ready(Err(ClientError::BadFormatDecipher.into()))),
        };
        // decode call
        let stf_call_signed = match TrustedCallSigned::decode(&mut request_vec.as_slice()) {
            Ok(call) => call,
            Err(_) => return Box::pin(ready(Err(ClientError::BadFormat.into()))),
        };
        //let best_block_hash = self.client.info().best_hash;
        // dummy block hash
        let best_block_hash = Default::default();
        Box::pin(
            self.pool
                .submit_one(
                    &generic::BlockId::hash(best_block_hash),
                    TX_SOURCE,
                    stf_call_signed,
                    shard,
                )
                .map_err(|e| {
                    StateRpcError::PoolError(
                        e.into_pool_error()
                            .map(Into::into)
                            .unwrap_or_else(|_e| PoolError::Verification),
                    )
                    .into()
                }),
        )
    }

    fn pending_calls(&self, shard: ShardIdentifier) -> Result<Vec<Vec<u8>>> {
        Ok(self
            .pool
            .ready(shard)
            .map(|tx| tx.data().encode().into())
            .collect())
    }

    fn get_shards(&self) -> Vec<ShardIdentifier> {
        self.pool.shards()
    }

    fn remove_call(
        &self,
        bytes_or_hash: Vec<hash::TrustedCallOrHash<TxHash<P>>>,
        shard: ShardIdentifier,
        inblock: bool,
    ) -> Result<Vec<TxHash<P>>> {
        let hashes = bytes_or_hash
            .into_iter()
            .map(|x| match x {
                hash::TrustedCallOrHash::Hash(h) => Ok(h),
                hash::TrustedCallOrHash::Call(bytes) => {
                    let xt = Decode::decode(&mut &bytes[..]).unwrap();
                    Ok(self.pool.hash_of(&xt))
                }
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(self
            .pool
            .remove_invalid(&hashes, shard, inblock)
            .into_iter()
            .map(|tx| tx.hash().clone())
            .collect())
    }

    fn watch_call(
        &self,
        ext: Vec<u8>,
        shard: ShardIdentifier,
    ) -> FutureResult<TxHash<P>, RpcError> {
        // decrypt call
        let rsa_keypair = rsa3072::unseal_pair().unwrap();
        let request_vec: Vec<u8> = match rsa3072::decrypt(&ext.as_slice(), &rsa_keypair) {
            Ok(req) => req,
            Err(_) => return Box::pin(ready(Err(ClientError::BadFormatDecipher.into()))),
        };
        // decode call
        let stf_call_signed = match TrustedCallSigned::decode(&mut request_vec.as_slice()) {
            Ok(call) => call,
            Err(_) => return Box::pin(ready(Err(ClientError::BadFormat.into()))),
        };
        //let best_block_hash = self.client.info().best_hash;
        // dummy block hash
        let best_block_hash = Default::default();
        Box::pin(
            self.pool
                .submit_and_watch(
                    &generic::BlockId::hash(best_block_hash),
                    TX_SOURCE,
                    stf_call_signed,
                    shard,
                )
                .map_err(|e| {
                    StateRpcError::PoolError(
                        e.into_pool_error()
                            .map(Into::into)
                            .unwrap_or_else(|_e| PoolError::Verification),
                    )
                    .into()
                }),
        )
    }
    
    /*	fn unwatch_extrinsic(&self, _metadata: Option<Self::Metadata>, id: SubscriptionId) -> Result<bool> {
        Ok(self.subscriptions.cancel(id))
    }*/
}
