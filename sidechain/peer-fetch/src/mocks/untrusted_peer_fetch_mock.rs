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

use crate::{error::Result, untrusted_peer_fetch::FetchUntrustedPeers};
use sidechain_primitives::types::ShardIdentifier;

pub struct UntrustedPeerFetcherMock {
	url: String,
}

impl UntrustedPeerFetcherMock {
	pub fn new(url: String) -> Self {
		UntrustedPeerFetcherMock { url }
	}
}

impl FetchUntrustedPeers for UntrustedPeerFetcherMock {
	fn get_untrusted_peer_url_of_shard(&self, _shard: &ShardIdentifier) -> Result<String> {
		Ok(self.url.clone())
	}
}
