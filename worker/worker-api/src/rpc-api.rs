// TODO: Adapt this copyright according to licencse

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

use jsonrpc_derive::rpc;
use jsonrpc_pubsub::{typed::Subscriber, SubscriptionId, manager::SubscriptionManager};
use sp_core::Bytes;
use sp_transaction_pool::TransactionStatus;
use self::error::{FutureResult, Result};

pub use self::gen_client::Client as AuthorClient;

/// Substrate authoring RPC API
#[rpc]
pub trait AuthorApi<Hash, BlockHash> {
	/// RPC metadata
	type Metadata;

	/// Submit hex-encoded extrinsic for inclusion in block.
	#[rpc(name = "author_submitExtrinsic")]
	fn submit_extrinsic(&self, extrinsic: Bytes) -> FutureResult<Hash>;

	/// Returns all pending extrinsics, potentially grouped by sender.
	#[rpc(name = "author_pendingExtrinsics")]
	fn pending_extrinsics(&self) -> Result<Vec<Bytes>>;

	/// Submit an extrinsic to watch.
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
		bytes: Bytes
    ); 

    /// All new head subscription
	fn subscribe_all_heads(
		&self,
		_metadata: crate::Metadata,
		subscriber: Subscriber<Block::Header>,
	) {
		subscribe_headers(
			self.client(),
			self.subscriptions(),
			subscriber,
			|| self.client().info().best_hash,
			|| self.client().import_notification_stream()
				.map(|notification| Ok::<_, ()>(notification.header))
				.compat(),
		)
	}
}

#[rpc]
pub trait ChainApi<Number, Hash, Header, SignedBlock> {
	/// RPC metadata
	type Metadata;

	/// All head subscription
	#[pubsub(subscription = "chain_allHead", subscribe, name = "chain_subscribeAllHeads")]
	fn subscribe_all_heads(&self, metadata: Self::Metadata, subscriber: Subscriber<Header>);

	/// Unsubscribe from all head subscription.
	#[pubsub(subscription = "chain_allHead", unsubscribe, name = "chain_unsubscribeAllHeads")]
	fn unsubscribe_all_heads(
		&self,
		metadata: Option<Self::Metadata>,
		id: SubscriptionId,
	) -> RpcResult<bool>;
}

/// Substrate state API
#[rpc]
pub trait StateApi<Hash> {
	/// RPC Metadata
	type Metadata;

	/// TODO: custom getter for either public data (permissionless) or private data (authenticated, only over wss://)
	#[rpc(name = "state_get")]
	fn get(&self, name: String, bytes: Bytes, hash: Option<Hash>) -> FutureResult<Bytes>;

	/// Returns the runtime metadata as an opaque blob.
	#[rpc(name = "state_getMetadata")]
	fn metadata(&self, hash: Option<Hash>) -> FutureResult<Bytes>;

	/// Get the runtime version.
	#[rpc(name = "state_getRuntimeVersion", alias("chain_getRuntimeVersion"))]
	fn runtime_version(&self, hash: Option<Hash>) -> FutureResult<RuntimeVersion>;
}


/// Substrate system RPC API
#[rpc]
pub trait SystemApi<Hash, Number> {
	/// Get the node's implementation name. Plain old string.
	#[rpc(name = "system_name")]
	fn system_name(&self) -> SystemResult<String>;

	/// Get the node implementation's version. Should be a semver string.
	#[rpc(name = "system_version")]
    fn system_version(&self) -> SystemResult<String>;
    
	/// Return health status of the node.
	///
	/// Node is considered healthy if it is:
	/// - connected to some peers (unless running in dev mode)
	/// - not performing a major sync
	#[rpc(name = "system_health", returns = "Health")]
	fn system_health(&self) -> Receiver<Health>;

}

//TODO: rpc_methods: what is meant with that?


