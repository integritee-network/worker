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

use crate::{connection_id_generator::ConnectionId, error::WebSocketResult, WebSocketConnection};

/// Mock implementation of a web socket connection.
#[derive(PartialEq, Eq, Hash, Default, Clone, Copy)]
pub(crate) struct WebSocketConnectionMock {
	id: ConnectionId,
}

impl WebSocketConnectionMock {
	pub fn new(id: ConnectionId) -> Self {
		WebSocketConnectionMock { id }
	}
}

impl WebSocketConnection for WebSocketConnectionMock {
	fn id(&self) -> ConnectionId {
		self.id
	}

	fn process_request<F>(&mut self, _initial_call: F) -> WebSocketResult<String>
	where
		F: Fn(&str) -> String,
	{
		Ok(Default::default())
	}

	fn send_update(&mut self, _message: &str) -> WebSocketResult<()> {
		Ok(())
	}

	fn close(&mut self) {}
}
