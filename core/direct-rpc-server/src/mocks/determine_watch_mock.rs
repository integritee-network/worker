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

use crate::{DetermineWatch, DirectRpcResult, RpcHash};
use itp_rpc::RpcResponse;

pub struct DetermineWatchMock<Hash>
where
	Hash: RpcHash,
{
	watch_next: Option<Hash>,
}

impl<Hash> DetermineWatchMock<Hash>
where
	Hash: RpcHash,
{
	#[allow(unused)]
	pub fn do_watch(hash: Hash) -> Self {
		DetermineWatchMock { watch_next: Some(hash) }
	}

	#[allow(unused)]
	pub fn no_watch() -> Self {
		DetermineWatchMock { watch_next: None }
	}
}

impl<Hash> DetermineWatch for DetermineWatchMock<Hash>
where
	Hash: RpcHash,
{
	type Hash = Hash;

	fn must_be_watched(&self, _rpc_response: &RpcResponse) -> DirectRpcResult<Option<Self::Hash>> {
		Ok(self.watch_next.clone())
	}
}
