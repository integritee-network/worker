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
use itp_api_client_extensions::PalletTeerexApi;
use its_primitives::types::ShardIdentifier;

/// Fetches the untrusted peer servers
/// FIXME: Should problably be combined with the peer fetch in
/// service/src/worker.rs
pub struct UntrustedPeerFetcher<NodeApi> {
	node_api: NodeApi,
}

impl<NodeApi> UntrustedPeerFetcher<NodeApi>
where
	NodeApi: PalletTeerexApi + Send + Sync,
{
	pub fn new(node_api: NodeApi) -> Self {
		UntrustedPeerFetcher { node_api }
	}
}

/// Trait to fetch untrusted peer servers.
pub trait FetchUntrustedPeers {
	fn get_untrusted_peer_url_of_shard(&self, shard: &ShardIdentifier) -> Result<String>;
}

impl<NodeApi> FetchUntrustedPeers for UntrustedPeerFetcher<NodeApi>
where
	NodeApi: PalletTeerexApi + Send + Sync,
{
	fn get_untrusted_peer_url_of_shard(&self, shard: &ShardIdentifier) -> Result<String> {
		let validateer = self
			.node_api
			.worker_for_shard(shard, None)?
			.ok_or(Error::NoPeerFoundForShard(*shard))?;
		let trusted_worker_client = DirectWorkerApi::new(validateer.url);
		Ok(trusted_worker_client.get_untrusted_worker_url()?)
	}
}
