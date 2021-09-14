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

use itc_direct_rpc_server::{DirectRpcResult, RpcHash, SendRpcResponse};
use itp_types::TrustedOperationStatus;
use std::{marker::PhantomData, vec::Vec};

pub struct RpcResponderMock<Hash> {
	_hash: PhantomData<Hash>,
}

impl<Hash> RpcResponderMock<Hash> {
	pub fn new() -> Self {
		RpcResponderMock { _hash: PhantomData }
	}
}

impl<Hash> SendRpcResponse for RpcResponderMock<Hash>
where
	Hash: RpcHash,
{
	type Hash = Hash;

	fn update_status_event(
		&self,
		_hash: Self::Hash,
		_status_update: TrustedOperationStatus,
	) -> DirectRpcResult<()> {
		Ok(())
	}

	fn send_state(&self, _hash: Self::Hash, _state_encoded: Vec<u8>) -> DirectRpcResult<()> {
		Ok(())
	}
}
