/*
	Copyright 2019 Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

use crate::{
	direct_invocation::{
		watch_list_service::WatchList,
		watching_client::{WatchingClient, WsSend},
	},
	ocall_bridge::bridge_api::{DirectInvocationBridge, OCallBridgeError, OCallBridgeResult},
};
use codec::{Decode, Encode};
use sp_core::H256 as Hash;
use std::sync::Arc;
use substratee_worker_primitives::{
	DirectRequestStatus, RpcResponse, RpcReturnValue, TrustedOperationStatus,
};

/// implementation of the direct invocation o-call
pub struct DirectInvocationOCall<W> {
	watch_list: Arc<W>,
}

impl<W> DirectInvocationOCall<W> {
	pub fn new(watch_list: Arc<W>) -> Self {
		DirectInvocationOCall { watch_list }
	}

	fn continue_watching(status: &TrustedOperationStatus) -> bool {
		!matches!(
			status,
			TrustedOperationStatus::Invalid
				| TrustedOperationStatus::InSidechainBlock(_)
				| TrustedOperationStatus::Finalized
				| TrustedOperationStatus::Usurped
		)
	}
}

impl<W> DirectInvocationBridge for DirectInvocationOCall<W>
where
	W: WatchList,
{
	fn update_status_event(
		&self,
		hash_vec: Vec<u8>,
		status_update_vec: Vec<u8>,
	) -> OCallBridgeResult<()> {
		let status_update = TrustedOperationStatus::decode(&mut status_update_vec.as_slice())
			.map_err(|e| OCallBridgeError::DirectInvocationError(format!("{:?}", e)))?;

		let hash = Hash::decode(&mut hash_vec.as_slice())
			.map_err(|e| OCallBridgeError::DirectInvocationError(format!("{:?}", e)))?;

		let continue_watching = match self.watch_list.get_watching_client(&hash) {
			Some(watched_client) => {
				let mut new_response = watched_client.rpc_response().clone();
				let old_result: Vec<u8> = new_response.result.clone();

				let mut result = RpcReturnValue::decode(&mut old_result.as_slice())
					.map_err(|e| OCallBridgeError::DirectInvocationError(format!("{:?}", e)))?;

				let do_watch = DirectInvocationOCall::<W>::continue_watching(&status_update);

				// update response
				result.do_watch = do_watch;
				result.status = DirectRequestStatus::TrustedOperationStatus(status_update);
				new_response.result = result.encode();

				let updated_client = watched_client.update_response(new_response);

				encode_and_send_response(&updated_client, updated_client.rpc_response())?;

				// update entire watching client object
				self.watch_list.add_watching_client(hash, updated_client);

				do_watch
			},
			None => false,
		};

		if !continue_watching {
			self.watch_list.remove_watching_client(&hash);
		}

		Ok(())
	}

	fn send_status(&self, hash_vec: Vec<u8>, status_vec: Vec<u8>) -> OCallBridgeResult<()> {
		let hash = Hash::decode(&mut hash_vec.as_slice())
			.map_err(|e| OCallBridgeError::DirectInvocationError(format!("{:?}", e)))?;

		if let Some(watched_client) = self.watch_list.get_watching_client(&hash) {
			let mut response = watched_client.rpc_response().clone();

			// create return value
			// TODO: Signature?
			let submitted =
				DirectRequestStatus::TrustedOperationStatus(TrustedOperationStatus::Submitted);
			let result = RpcReturnValue::new(status_vec, false, submitted);

			// update response
			response.result = result.encode();

			encode_and_send_response(&watched_client, &response)?;

			watched_client
				.close()
				.map_err(|e| OCallBridgeError::DirectInvocationError(format!("{:?}", e)))?;
		};

		self.watch_list.remove_watching_client(&hash);

		Ok(())
	}
}

fn encode_and_send_response<S: WsSend>(
	sender: &S,
	rpc_response: &RpcResponse,
) -> OCallBridgeResult<()> {
	let string_response = serde_json::to_string(&rpc_response)
		.map_err(|e| OCallBridgeError::DirectInvocationError(format!("{:?}", e)))?;

	sender
		.send(string_response)
		.map_err(|e| OCallBridgeError::DirectInvocationError(format!("{:?}", e)))
}

#[cfg(test)]
pub mod tests {

	use super::*;

	#[test]
	fn test_continue_watching() {
		assert!(!DirectInvocationOCall::<()>::continue_watching(&TrustedOperationStatus::Invalid));
		assert!(!DirectInvocationOCall::<()>::continue_watching(&TrustedOperationStatus::Usurped));
		assert!(DirectInvocationOCall::<()>::continue_watching(&TrustedOperationStatus::Future));
		assert!(DirectInvocationOCall::<()>::continue_watching(&TrustedOperationStatus::Broadcast));
		assert!(DirectInvocationOCall::<()>::continue_watching(&TrustedOperationStatus::Dropped));
	}
}
