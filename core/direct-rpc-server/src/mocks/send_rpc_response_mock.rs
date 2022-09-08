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

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::{DirectRpcResult, RpcHash, SendRpcResponse};
use itp_types::TrustedOperationStatus;
use std::vec::Vec;

/// Send RPC response mock.
#[derive(Default)]
pub struct SendRpcResponseMock<HashType> {
	pub sent_states: RwLock<Vec<(HashType, Vec<u8>)>>,
}

impl<HashType> SendRpcResponse for SendRpcResponseMock<HashType>
where
	HashType: RpcHash,
{
	type Hash = HashType;

	fn update_status_event(
		&self,
		_hash: Self::Hash,
		_status_update: TrustedOperationStatus,
	) -> DirectRpcResult<()> {
		unimplemented!()
	}

	fn send_state(&self, hash: Self::Hash, state_encoded: Vec<u8>) -> DirectRpcResult<()> {
		let mut states_lock = self.sent_states.write().unwrap();
		states_lock.push((hash, state_encoded));
		Ok(())
	}
}
