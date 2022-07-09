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

use crate::{error::WebSocketResult, WebSocketConnection};
use mio::{Event, Evented, Poll, PollOpt, Ready, Token};
use std::vec::Vec;
use tungstenite::Message;

/// Mock implementation of a web socket connection.
#[derive(PartialEq, Eq, Clone)]
pub(crate) struct WebSocketConnectionMock {
	pub id: Token,
	pub messages_to_read: Vec<Message>,
	pub messages_written: Vec<Message>,
	pub is_closed: bool,
	socket: SocketMock,
}

impl WebSocketConnectionMock {
	#[allow(unused)]
	pub fn new(id: Token) -> Self {
		WebSocketConnectionMock {
			id,
			messages_to_read: Default::default(),
			messages_written: Default::default(),
			is_closed: false,
			socket: SocketMock {},
		}
	}

	#[allow(unused)]
	pub fn with_messages_to_read(mut self, messages: Vec<Message>) -> Self {
		self.messages_to_read = messages;
		self
	}
}

impl WebSocketConnection for WebSocketConnectionMock {
	type Socket = SocketMock;

	fn socket(&self) -> Option<&Self::Socket> {
		Some(&self.socket)
	}

	fn get_session_readiness(&self) -> Ready {
		Ready::readable()
	}

	fn on_ready(&mut self, _poll: &mut Poll, _ev: &Event) -> WebSocketResult<()> {
		Ok(())
	}

	fn is_closed(&self) -> bool {
		self.is_closed
	}

	fn token(&self) -> Token {
		self.id
	}
}

#[derive(PartialEq, Eq, Clone)]
pub(crate) struct SocketMock;

impl Evented for SocketMock {
	fn register(
		&self,
		_poll: &Poll,
		_token: Token,
		_interest: Ready,
		_opts: PollOpt,
	) -> std::io::Result<()> {
		Ok(())
	}

	fn reregister(
		&self,
		_poll: &Poll,
		_token: Token,
		_interest: Ready,
		_opts: PollOpt,
	) -> std::io::Result<()> {
		Ok(())
	}

	fn deregister(&self, _poll: &Poll) -> std::io::Result<()> {
		Ok(())
	}
}
