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

use crate::{WebSocketMessageHandler, WebSocketResult};
use log::debug;
use mio::Token;
use std::{string::String, vec::Vec};

pub struct WebSocketHandlerMock {
	pub response: Option<String>,
	pub messages_handled: RwLock<Vec<(Token, String)>>,
}

impl WebSocketHandlerMock {
	pub fn new(response: Option<String>) -> Self {
		WebSocketHandlerMock { response, messages_handled: Default::default() }
	}

	pub fn get_handled_messages(&self) -> Vec<(Token, String)> {
		self.messages_handled.read().unwrap().clone()
	}
}

impl WebSocketMessageHandler for WebSocketHandlerMock {
	fn handle_message(
		&self,
		connection_token: Token,
		message: String,
	) -> WebSocketResult<Option<String>> {
		let mut handled_messages_lock = self.messages_handled.write().unwrap();

		debug!("Handling message: {}", message);
		handled_messages_lock.push((connection_token, message));

		Ok(self.response.clone())
	}
}
