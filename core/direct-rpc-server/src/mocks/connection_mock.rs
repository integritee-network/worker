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

use crate::mocks::updates_sink::UpdatesSink;
use itc_tls_websocket_server::{WebSocketConnection, WebSocketResult};
use std::{string::String, sync::Arc};

pub struct ConnectionMock {
	name: String,
	input: Option<String>,
	maybe_updates_sink: Option<Arc<UpdatesSink>>,
	is_closed: bool,
}

impl ConnectionMock {
	pub fn builder() -> ConnectionMockBuilder {
		ConnectionMockBuilder::new()
	}

	pub fn name(&self) -> &String {
		&self.name
	}

	pub fn is_closed(&self) -> bool {
		self.is_closed
	}
}

impl WebSocketConnection for ConnectionMock {
	fn process_request<F>(&mut self, initial_call: F) -> WebSocketResult<String>
	where
		F: Fn(&str) -> String,
	{
		match &self.input {
			Some(i) => Ok((initial_call)(i.as_str())),
			None => Ok("processed".to_string()),
		}
	}

	fn send_update(&mut self, message: String) -> WebSocketResult<()> {
		if let Some(updates_sink) = self.maybe_updates_sink.as_ref() {
			updates_sink.push_update(String::from(message));
		}
		Ok(())
	}

	fn close(&mut self) {
		self.is_closed = true;
	}
}

/// builder pattern for the connection mock
pub struct ConnectionMockBuilder {
	maybe_name: Option<String>,
	maybe_input: Option<String>,
	maybe_is_closed: Option<bool>,
	maybe_updates_sink: Option<Arc<UpdatesSink>>,
}

impl ConnectionMockBuilder {
	/// use with ConnectionMock::builder()
	fn new() -> Self {
		ConnectionMockBuilder {
			maybe_name: None,
			maybe_input: None,
			maybe_is_closed: None,
			maybe_updates_sink: None,
		}
	}

	pub fn with_name(mut self, name: &str) -> Self {
		self.maybe_name = Some(String::from(name));
		self
	}

	pub fn with_input(mut self, input: &str) -> Self {
		self.maybe_input = Some(String::from(input));
		self
	}

	pub fn with_updates_sink(mut self, updates_sink: Arc<UpdatesSink>) -> Self {
		self.maybe_updates_sink = Some(updates_sink);
		self
	}

	pub fn build(self) -> ConnectionMock {
		let name = self.maybe_name.unwrap_or("blank".to_string());
		let input = self.maybe_input;
		let is_closed = self.maybe_is_closed.unwrap_or(false);
		let updates_sink = self.maybe_updates_sink;

		ConnectionMock { name, input, maybe_updates_sink: updates_sink, is_closed }
	}
}
