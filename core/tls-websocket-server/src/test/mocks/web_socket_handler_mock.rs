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

use crate::{
	test::mocks::web_socket_connection_mock::WebSocketConnectionMock, ConnectionId,
	WebSocketHandler, WebSocketResult,
};
use std::{string::String, vec::Vec};

pub struct WebSocketHandlerMock {
	pub response: Option<String>,
	pub messages_handled: RwLock<Vec<(ConnectionId, String)>>,
}

impl WebSocketHandlerMock {
	pub fn new(response: Option<String>) -> Self {
		WebSocketHandlerMock { response, messages_handled: Default::default() }
	}
}

impl WebSocketHandler for WebSocketHandlerMock {
	type Connection = WebSocketConnectionMock;

	fn handle(&self, _connection: Self::Connection) -> WebSocketResult<()> {
		todo!()
	}

	fn handle_message(
		&self,
		connection_id: ConnectionId,
		message: String,
	) -> WebSocketResult<Option<String>> {
		let handled_messages_lock = self.messages_handled.write().unwrap();

		handled_messages_lock.push((connection_id, message));

		Ok(self.response.clone())
	}
}
