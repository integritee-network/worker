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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{DetermineWatch, RpcConnectionRegistry, RpcHash};
use itc_tls_websocket_server::{error::WebSocketResult, ConnectionToken, WebSocketMessageHandler};
use jsonrpc_core::IoHandler;
use log::*;
use std::{string::String, sync::Arc};

pub struct RpcWsHandler<Watcher, Registry, Hash>
where
	Watcher: DetermineWatch<Hash = Hash>,
	Registry: RpcConnectionRegistry<Hash = Hash>,
	Hash: RpcHash,
{
	rpc_io_handler: IoHandler,
	connection_watcher: Arc<Watcher>,
	connection_registry: Arc<Registry>,
}

impl<Watcher, Registry, Hash> RpcWsHandler<Watcher, Registry, Hash>
where
	Watcher: DetermineWatch<Hash = Hash>,
	Registry: RpcConnectionRegistry<Hash = Hash>,
	Hash: RpcHash,
{
	pub fn new(
		rpc_io_handler: IoHandler,
		connection_watcher: Arc<Watcher>,
		connection_registry: Arc<Registry>,
	) -> Self {
		RpcWsHandler { rpc_io_handler, connection_watcher, connection_registry }
	}
}

impl<Watcher, Registry, Hash> WebSocketMessageHandler for RpcWsHandler<Watcher, Registry, Hash>
where
	Watcher: DetermineWatch<Hash = Hash>,
	Registry: RpcConnectionRegistry<Hash = Hash>,
	Registry::Connection: From<ConnectionToken>,
	Hash: RpcHash,
{
	fn handle_message(
		&self,
		connection_token: ConnectionToken,
		message: String,
	) -> WebSocketResult<Option<String>> {
		let maybe_rpc_response = self.rpc_io_handler.handle_request_sync(message.as_str());

		debug!("RPC response string: {:?}", maybe_rpc_response);

		if let Ok(rpc_response) =
			serde_json::from_str(maybe_rpc_response.clone().unwrap_or_default().as_str())
		{
			if let Ok(Some(connection_hash)) =
				self.connection_watcher.must_be_watched(&rpc_response)
			{
				self.connection_registry.store(
					connection_hash,
					connection_token.into(),
					rpc_response,
				);
			}
		}

		Ok(maybe_rpc_response)
	}
}

#[cfg(test)]
pub mod tests {

	use super::*;
	use crate::{
		mocks::determine_watch_mock::DetermineWatchMock,
		rpc_connection_registry::ConnectionRegistry,
	};
	use codec::Encode;
	use itc_tls_websocket_server::ConnectionToken;
	use itp_rpc::RpcReturnValue;
	use itp_types::DirectRequestStatus;
	use itp_utils::ToHexPrefixed;
	use jsonrpc_core::Params;
	use serde_json::json;

	type TestConnectionRegistry = ConnectionRegistry<String, ConnectionToken>;
	type TestConnectionWatcher = DetermineWatchMock<String>;
	type TestWsHandler = RpcWsHandler<TestConnectionWatcher, TestConnectionRegistry, String>;

	const RPC_METHOD_NAME: &str = "test_call";

	#[test]
	fn valid_rpc_call_without_watch_runs_successfully() {
		let io_handler = create_io_handler_with_method(RPC_METHOD_NAME);

		let (connection_token, message) = create_message_to_handle(RPC_METHOD_NAME);

		let (ws_handler, connection_registry) = create_ws_handler(io_handler, None);

		let handle_result = ws_handler.handle_message(connection_token, message);

		assert!(handle_result.is_ok());
		assert!(connection_registry.is_empty());
	}

	#[test]
	fn valid_rpc_call_with_watch_runs_successfully_and_stores_connection() {
		let io_handler = create_io_handler_with_method(RPC_METHOD_NAME);

		let connection_hash = String::from("connection_hash");
		let (connection_token, message) = create_message_to_handle(RPC_METHOD_NAME);

		let (ws_handler, connection_registry) =
			create_ws_handler(io_handler, Some(connection_hash.clone()));

		let handle_result = ws_handler.handle_message(connection_token, message);

		assert!(handle_result.is_ok());
		assert!(connection_registry.withdraw(&connection_hash).is_some());
	}

	#[test]
	fn when_rpc_returns_error_then_return_ok_but_status_is_set_to_error() {
		let io_handler = create_io_handler_with_error(RPC_METHOD_NAME);

		let connection_hash = String::from("connection_hash");
		let (connection_token, message) = create_message_to_handle(RPC_METHOD_NAME);

		let (ws_handler, connection_registry) =
			create_ws_handler(io_handler, Some(connection_hash.clone()));

		let handle_result = ws_handler.handle_message(connection_token, message);

		assert!(handle_result.is_ok());
		assert!(connection_registry.withdraw(&connection_hash).is_some());
	}

	#[test]
	fn when_rpc_method_does_not_match_anything_return_json_error_message() {
		let io_handler = create_io_handler_with_error(RPC_METHOD_NAME);
		let (connection_token, message) = create_message_to_handle("not_a_valid_method");

		let (ws_handler, connection_registry) = create_ws_handler(io_handler, None);

		let handle_result = ws_handler.handle_message(connection_token, message).unwrap().unwrap();

		assert_eq!(handle_result, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":1}");
		assert!(connection_registry.is_empty());
	}

	fn create_message_to_handle(method_name: &str) -> (ConnectionToken, String) {
		let json_rpc_pre_method = r#"{"jsonrpc": "2.0", "method": ""#;
		let json_rpc_post_method = r#"", "params": {}, "id": 1}"#;

		let json_string = format!("{}{}{}", json_rpc_pre_method, method_name, json_rpc_post_method);
		debug!("JSON input: {}", json_string);

		(ConnectionToken(23), json_string)
	}

	fn create_ws_handler(
		io_handler: IoHandler,
		watch_connection: Option<String>,
	) -> (TestWsHandler, Arc<TestConnectionRegistry>) {
		let watcher = match watch_connection {
			Some(hash) => TestConnectionWatcher::do_watch(hash),
			None => TestConnectionWatcher::no_watch(),
		};

		let connection_registry = Arc::new(TestConnectionRegistry::new());

		(
			TestWsHandler::new(io_handler, Arc::new(watcher), connection_registry.clone()),
			connection_registry,
		)
	}

	fn create_io_handler_with_method(method_name: &str) -> IoHandler {
		create_io_handler(
			method_name,
			RpcReturnValue {
				do_watch: false,
				value: String::from("value").encode(),
				status: DirectRequestStatus::Ok,
			},
		)
	}

	fn create_io_handler_with_error(method_name: &str) -> IoHandler {
		create_io_handler(
			method_name,
			RpcReturnValue {
				value: "error!".encode(),
				do_watch: false,
				status: DirectRequestStatus::Error,
			},
		)
	}

	fn create_io_handler<ReturnValue>(method_name: &str, return_value: ReturnValue) -> IoHandler
	where
		ReturnValue: Encode + Send + Sync + 'static,
	{
		let mut io_handler = IoHandler::new();
		io_handler.add_sync_method(method_name, move |_: Params| Ok(json!(return_value.to_hex())));
		io_handler
	}
}
