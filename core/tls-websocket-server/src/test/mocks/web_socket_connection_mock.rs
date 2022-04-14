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
	error::{WebSocketError, WebSocketResult},
	WebSocketConnection,
};
use mio::Token;
use std::vec::Vec;
use tungstenite::Message;

/// Mock implementation of a web socket connection.
#[derive(PartialEq, Eq, Clone)]
pub(crate) struct WebSocketConnectionMock {
	pub id: Token,
	pub messages_to_read: Vec<Message>,
	pub messages_written: Vec<Message>,
	pub is_closed: bool,
}

impl WebSocketConnectionMock {
	pub fn new(id: Token) -> Self {
		WebSocketConnectionMock {
			id,
			messages_to_read: Default::default(),
			messages_written: Default::default(),
			is_closed: false,
		}
	}

	pub fn with_messages_to_read(mut self, messages: Vec<Message>) -> Self {
		self.messages_to_read = messages;
		self
	}
}

impl WebSocketConnection for WebSocketConnectionMock {
	fn id(&self) -> Token {
		self.id
	}

	fn read_message(&mut self) -> WebSocketResult<Message> {
		self.messages_to_read.pop().ok_or(WebSocketError::ConnectionClosed)
	}

	fn write_pending(&mut self) -> WebSocketResult<()> {
		todo!()
	}

	fn process_request<F>(&mut self, _initial_call: F) -> WebSocketResult<String>
	where
		F: Fn(&str) -> String,
	{
		Ok(Default::default())
	}

	fn send_update(&mut self, message: String) -> WebSocketResult<()> {
		self.messages_written.push(Message::Text(message));
		Ok(())
	}

	fn close(&mut self) {
		self.is_closed = true;
	}
}
