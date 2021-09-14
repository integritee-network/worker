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

extern crate alloc;

use crate::{DetermineWatch, DirectRpcError, RpcConnectionRegistry, RpcHash};
use alloc::boxed::Box;
use itc_tls_websocket_server::{
	WebSocketConnection, WebSocketError, WebSocketHandler, WebSocketResult,
};
use jsonrpc_core::IoHandler;
use log::*;
use std::sync::Arc;

pub struct RpcWsHandler<Watcher, Registry, Hash, Connection>
where
	Watcher: DetermineWatch<Hash = Hash>,
	Registry: RpcConnectionRegistry<Hash = Hash, Connection = Connection>,
	Hash: RpcHash,
	Connection: WebSocketConnection,
{
	rpc_io_handler: IoHandler,
	connection_watcher: Arc<Watcher>,
	connection_registry: Arc<Registry>,
}

impl<Watcher, Registry, Hash, Connection> RpcWsHandler<Watcher, Registry, Hash, Connection>
where
	Watcher: DetermineWatch<Hash = Hash>,
	Registry: RpcConnectionRegistry<Hash = Hash, Connection = Connection>,
	Hash: RpcHash,
	Connection: WebSocketConnection,
{
	pub fn new(
		rpc_io_handler: IoHandler,
		connection_watcher: Arc<Watcher>,
		connection_registry: Arc<Registry>,
	) -> Self {
		RpcWsHandler { rpc_io_handler, connection_watcher, connection_registry }
	}
}

impl<Watcher, Registry, Hash, Connection> WebSocketHandler
	for RpcWsHandler<Watcher, Registry, Hash, Connection>
where
	Watcher: DetermineWatch<Hash = Hash>,
	Registry: RpcConnectionRegistry<Hash = Hash, Connection = Connection>,
	Hash: RpcHash,
	Connection: WebSocketConnection,
{
	type Connection = Connection;

	fn handle(&self, mut connection: Connection) -> WebSocketResult<()> {
		let rpc_response_string = connection.process_request(|request| {
			self.rpc_io_handler.handle_request_sync(request).unwrap_or_default()
		})?;

		debug!("RPC response string: {}", rpc_response_string);

		let rpc_response = serde_json::from_str(&rpc_response_string).map_err(|e| {
			WebSocketError::HandlerError(Box::new(DirectRpcError::SerializationError(e)))
		})?;

		match self.connection_watcher.must_be_watched(&rpc_response) {
			Ok(maybe_connection_hash) => {
				if let Some(connection_hash) = maybe_connection_hash {
					debug!("current connection is kept alive");
					self.connection_registry.store(connection_hash, connection, rpc_response);
				}
				Ok(())
			},
			Err(e) => Err(WebSocketError::HandlerError(Box::new(e))),
		}
	}
}

#[cfg(test)]
pub mod tests {

	use super::*;
	use crate::{
		mocks::{connection_mock::ConnectionMock, determine_watch_mock::DetermineWatchMock},
		rpc_connection_registry::ConnectionRegistry,
	};
	use codec::Encode;
	use itp_types::{DirectRequestStatus, RpcReturnValue};
	use jsonrpc_core::Params;
	use serde_json::json;

	type TestConnection = ConnectionMock;
	type TestConnectionRegistry = ConnectionRegistry<String, TestConnection>;
	type TestConnectionWatcher = DetermineWatchMock<String>;
	type TestWsHandler =
		RpcWsHandler<TestConnectionWatcher, TestConnectionRegistry, String, TestConnection>;

	const RPC_METHOD_NAME: &str = "test_call";

	#[test]
	fn valid_rpc_call_without_watch_runs_successfully() {
		let io_handler = create_io_handler_with_method(RPC_METHOD_NAME);

		let connection = create_connection(RPC_METHOD_NAME);

		let (ws_handler, connection_registry) = create_ws_handler(io_handler, None);

		let handle_result = ws_handler.handle(connection);

		assert!(handle_result.is_ok());
		assert!(connection_registry.is_empty());
	}

	#[test]
	fn valid_rpc_call_with_watch_runs_successfully_and_stores_connection() {
		let io_handler = create_io_handler_with_method(RPC_METHOD_NAME);

		let connection_hash = String::from("connection_hash");
		let connection = create_connection(RPC_METHOD_NAME);

		let (ws_handler, connection_registry) =
			create_ws_handler(io_handler, Some(connection_hash.clone()));

		let handle_result = ws_handler.handle(connection);

		assert!(handle_result.is_ok());
		assert!(connection_registry.withdraw(&connection_hash).is_some());
	}

	#[test]
	fn when_rpc_returns_error_then_return_ok_but_status_is_set_to_error() {
		let io_handler = create_io_handler_with_error(RPC_METHOD_NAME);

		let connection_hash = String::from("connection_hash");
		let connection = create_connection(RPC_METHOD_NAME);

		let (ws_handler, connection_registry) =
			create_ws_handler(io_handler, Some(connection_hash.clone()));

		let handle_result = ws_handler.handle(connection);

		assert!(handle_result.is_ok());
		assert!(connection_registry.withdraw(&connection_hash).is_some());
	}

	#[test]
	fn when_rpc_method_does_not_match_anything_return_error() {
		let io_handler = create_io_handler_with_error(RPC_METHOD_NAME);
		let connection = create_connection("not_a_valid_method");

		let (ws_handler, connection_registry) = create_ws_handler(io_handler, None);

		let handle_result = ws_handler.handle(connection);

		assert_matches!(handle_result, Err(WebSocketError::HandlerError(_)));
		assert!(connection_registry.is_empty());
	}

	fn create_connection(method_name: &str) -> ConnectionMock {
		let json_rpc_pre_method = r#"{"jsonrpc": "2.0", "method": ""#;
		let json_rpc_post_method = r#"", "params": {}, "id": 1}"#;

		let json_string = format!("{}{}{}", json_rpc_pre_method, method_name, json_rpc_post_method);
		debug!("JSON input: {}", json_string);

		TestConnection::builder().with_input(json_string.as_str()).build()
	}

	fn create_ws_handler(
		io_handler: IoHandler,
		watch_connection: Option<String>,
	) -> (TestWsHandler, Arc<TestConnectionRegistry>) {
		let watcher = match watch_connection {
			Some(hash) => TestConnectionWatcher::do_watch(hash),
			None => TestConnectionWatcher::no_watch(),
		};

		let connection_registry = Arc::new(ConnectionRegistry::<String, TestConnection>::new());

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
		io_handler.add_method(method_name, move |_: Params| Ok(json!(return_value.encode())));
		io_handler
	}
}
