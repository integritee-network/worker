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

use crate::error::{Error, Result};
use itc_rpc_client::direct_client::{DirectApi, DirectClient as DirectWorkerApi};
use itp_node_api::{api_client::PalletTeerexApi, node_api_factory::CreateNodeApi};
use its_primitives::types::ShardIdentifier;
use std::sync::Arc;

/// Trait to fetch untrusted peer servers.
pub trait FetchUntrustedPeers {
	fn get_untrusted_peer_url_of_shard(&self, shard: &ShardIdentifier) -> Result<String>;
}

/// Fetches the untrusted peer servers
/// FIXME: Should probably be combined with the peer fetch in
/// service/src/worker.rs
pub struct UntrustedPeerFetcher<NodeApiFactory> {
	node_api_factory: Arc<NodeApiFactory>,
}

impl<NodeApiFactory> UntrustedPeerFetcher<NodeApiFactory>
where
	NodeApiFactory: CreateNodeApi + Send + Sync,
{
	pub fn new(node_api: Arc<NodeApiFactory>) -> Self {
		UntrustedPeerFetcher { node_api_factory: node_api }
	}
}

impl<NodeApiFactory> FetchUntrustedPeers for UntrustedPeerFetcher<NodeApiFactory>
where
	NodeApiFactory: CreateNodeApi + Send + Sync,
{
	fn get_untrusted_peer_url_of_shard(&self, shard: &ShardIdentifier) -> Result<String> {
		let node_api = self.node_api_factory.create_api()?;

		let validateer = node_api
			.primary_worker_for_shard(shard, None)?
			.ok_or_else(|| Error::NoPeerFoundForShard(*shard))?;

		let trusted_worker_client = DirectWorkerApi::new(
			validateer
				.instance_url()
				.map(|url| String::from_utf8(url).unwrap_or_default())
				.ok_or_else(|| Error::NoPeerFoundForShard(*shard))?,
		);
		Ok(trusted_worker_client.get_untrusted_worker_url()?)
	}
}
