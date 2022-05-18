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

use crate::{
	response_channel::ResponseChannel, DirectRpcError, DirectRpcResult, RpcConnectionRegistry,
	RpcHash, SendRpcResponse,
};
use itp_types::{DirectRequestStatus, RpcResponse, RpcReturnValue, TrustedOperationStatus};
use itp_utils::{FromHexPrefixed, ToHexPrefixed};
use log::*;
use std::{boxed::Box, sync::Arc, vec::Vec};

pub struct RpcResponder<Registry, Hash, ResponseChannelType>
where
	Registry: RpcConnectionRegistry<Hash = Hash>,
	Hash: RpcHash,
	ResponseChannelType: ResponseChannel<Registry::Connection>,
{
	connection_registry: Arc<Registry>,
	response_channel: Arc<ResponseChannelType>,
}

impl<Registry, Hash, ResponseChannelType> RpcResponder<Registry, Hash, ResponseChannelType>
where
	Registry: RpcConnectionRegistry<Hash = Hash>,
	Hash: RpcHash,
	ResponseChannelType: ResponseChannel<Registry::Connection>,
{
	pub fn new(
		connection_registry: Arc<Registry>,
		web_socket_responder: Arc<ResponseChannelType>,
	) -> Self {
		RpcResponder { connection_registry, response_channel: web_socket_responder }
	}

	fn encode_and_send_response(
		&self,
		connection: Registry::Connection,
		rpc_response: &RpcResponse,
	) -> DirectRpcResult<()> {
		let string_response =
			serde_json::to_string(&rpc_response).map_err(DirectRpcError::SerializationError)?;

		self.response_channel.respond(connection, string_response).map_err(|e| e.into())
	}
}

impl<Registry, Hash, ResponseChannelType> SendRpcResponse
	for RpcResponder<Registry, Hash, ResponseChannelType>
where
	Registry: RpcConnectionRegistry<Hash = Hash>,
	Hash: RpcHash,
	ResponseChannelType: ResponseChannel<Registry::Connection>,
{
	type Hash = Hash;

	fn update_status_event(
		&self,
		hash: Hash,
		status_update: TrustedOperationStatus,
	) -> DirectRpcResult<()> {
		debug!("updating status event");

		// withdraw removes it from the registry
		let (connection_token, rpc_response) = self
			.connection_registry
			.withdraw(&hash)
			.ok_or(DirectRpcError::InvalidConnectionHash)?;

		let mut new_response = rpc_response.clone();

		let mut result = RpcReturnValue::from_hex(&rpc_response.result)
			.map_err(|e| DirectRpcError::Other(Box::new(e)))?;

		let do_watch = continue_watching(&status_update);

		// update response
		result.do_watch = do_watch;
		result.status = DirectRequestStatus::TrustedOperationStatus(status_update);
		new_response.result = result.to_hex();

		self.encode_and_send_response(connection_token, &new_response)?;

		if do_watch {
			self.connection_registry.store(hash, connection_token, new_response);
		}

		debug!("updating status event successful");
		Ok(())
	}

	fn send_state(&self, hash: Hash, state_encoded: Vec<u8>) -> DirectRpcResult<()> {
		debug!("sending state");

		// withdraw removes it from the registry
		let (connection_token, mut response) = self
			.connection_registry
			.withdraw(&hash)
			.ok_or(DirectRpcError::InvalidConnectionHash)?;

		// create return value
		// TODO: Signature?
		let submitted =
			DirectRequestStatus::TrustedOperationStatus(TrustedOperationStatus::Submitted);
		let result = RpcReturnValue::new(state_encoded, false, submitted);

		// update response
		response.result = result.to_hex();

		self.encode_and_send_response(connection_token, &response)?;

		self.connection_registry.store(hash, connection_token, response);

		debug!("sending state successful");
		Ok(())
	}
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

#[cfg(test)]
pub mod tests {

	use super::*;
	use crate::{
		builders::rpc_response_builder::RpcResponseBuilder,
		mocks::response_channel_mock::ResponseChannelMock,
		rpc_connection_registry::ConnectionRegistry,
	};
	use codec::Encode;
	use std::assert_matches::assert_matches;

	type TestConnectionToken = u64;
	type TestResponseChannel = ResponseChannelMock<TestConnectionToken>;
	type TestConnectionRegistry = ConnectionRegistry<String, TestConnectionToken>;

	#[test]
	fn given_empty_registry_when_updating_status_event_then_return_error() {
		let connection_registry = Arc::new(TestConnectionRegistry::new());
		let websocket_responder = Arc::new(TestResponseChannel::default());
		let rpc_responder = RpcResponder::new(connection_registry, websocket_responder);

		assert_matches!(
			rpc_responder
				.update_status_event("hash".to_string(), TrustedOperationStatus::Broadcast),
			Err(DirectRpcError::InvalidConnectionHash)
		);
	}

	#[test]
	fn given_empty_registry_when_sending_state_then_return_error() {
		let connection_registry = Arc::new(TestConnectionRegistry::new());
		let websocket_responder = Arc::new(TestResponseChannel::default());
		let rpc_responder = RpcResponder::new(connection_registry, websocket_responder);

		assert_matches!(
			rpc_responder.send_state("hash".to_string(), vec![1u8, 2u8]),
			Err(DirectRpcError::InvalidConnectionHash)
		);
	}

	#[test]
	fn updating_status_event_with_finalized_state_removes_connection() {
		let connection_hash = String::from("conn_hash");
		let connection_registry = create_registry_with_single_connection(connection_hash.clone());

		let websocket_responder = Arc::new(TestResponseChannel::default());
		let rpc_responder =
			RpcResponder::new(connection_registry.clone(), websocket_responder.clone());

		let result = rpc_responder
			.update_status_event(connection_hash.clone(), TrustedOperationStatus::Finalized);

		assert!(result.is_ok());

		verify_closed_connection(&connection_hash, connection_registry);
		assert_eq!(1, websocket_responder.number_of_updates());
	}

	#[test]
	fn updating_status_event_with_ready_state_keeps_connection_and_sends_update() {
		let connection_hash = String::from("conn_hash");
		let connection_registry = create_registry_with_single_connection(connection_hash.clone());

		let websocket_responder = Arc::new(TestResponseChannel::default());
		let rpc_responder =
			RpcResponder::new(connection_registry.clone(), websocket_responder.clone());

		let first_result = rpc_responder
			.update_status_event(connection_hash.clone(), TrustedOperationStatus::Ready);

		let second_result = rpc_responder
			.update_status_event(connection_hash.clone(), TrustedOperationStatus::Submitted);

		assert!(first_result.is_ok());
		assert!(second_result.is_ok());

		verify_open_connection(&connection_hash, connection_registry);
		assert_eq!(2, websocket_responder.number_of_updates());
	}

	#[test]
	fn sending_state_successfully_sends_update_and_keeps_connection_open() {
		let connection_hash = String::from("conn_hash");
		let connection_registry = create_registry_with_single_connection(connection_hash.clone());

		let websocket_responder = Arc::new(TestResponseChannel::default());
		let rpc_responder =
			RpcResponder::new(connection_registry.clone(), websocket_responder.clone());

		let result = rpc_responder.send_state(connection_hash.clone(), "new_state".encode());
		assert!(result.is_ok());

		verify_open_connection(&connection_hash, connection_registry);
		assert_eq!(1, websocket_responder.number_of_updates());
	}

	#[test]
	fn sending_state_twice_works() {
		let connection_hash = String::from("conn_hash");
		let connection_registry = create_registry_with_single_connection(connection_hash.clone());

		let websocket_responder = Arc::new(TestResponseChannel::default());
		let rpc_responder =
			RpcResponder::new(connection_registry.clone(), websocket_responder.clone());

		let first_result = rpc_responder.send_state(connection_hash.clone(), "new_state".encode());
		assert!(first_result.is_ok());

		let second_result =
			rpc_responder.send_state(connection_hash.clone(), "new_state_2".encode());
		assert!(second_result.is_ok());

		assert_eq!(2, websocket_responder.number_of_updates());
	}

	#[test]
	fn test_continue_watching() {
		assert!(!continue_watching(&TrustedOperationStatus::Invalid));
		assert!(!continue_watching(&TrustedOperationStatus::Usurped));
		assert!(continue_watching(&TrustedOperationStatus::Future));
		assert!(continue_watching(&TrustedOperationStatus::Broadcast));
		assert!(continue_watching(&TrustedOperationStatus::Dropped));
	}

	fn verify_open_connection(
		connection_hash: &String,
		connection_registry: Arc<TestConnectionRegistry>,
	) {
		let maybe_connection = connection_registry.withdraw(&connection_hash);
		assert!(maybe_connection.is_some());
	}

	fn verify_closed_connection(
		connection_hash: &String,
		connection_registry: Arc<TestConnectionRegistry>,
	) {
		assert!(connection_registry.withdraw(&connection_hash).is_none());
	}

	fn create_registry_with_single_connection(
		connection_hash: String,
	) -> Arc<TestConnectionRegistry> {
		let connection_registry = TestConnectionRegistry::new();
		let rpc_response = RpcResponseBuilder::new().with_id(2).build();

		connection_registry.store(connection_hash.clone(), 1, rpc_response);
		Arc::new(connection_registry)
	}
}
