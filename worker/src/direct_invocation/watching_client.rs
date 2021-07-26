/*
	Copyright 2019 Supercomputing Systems AG

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

use substratee_worker_primitives::RpcResponse;
use ws::{CloseCode, Message, Result, Sender};

/// trait to create a watching client instance
/// concrete WatchingClient is abstracted, allowing to mock
pub trait CreateWatchingClient {
	type Client: WatchingClient;

	fn create(&self, rpc_response: RpcResponse) -> Self::Client;
}

/// wrapper trait for ws::Sender, because it does not provide any abstraction itself
pub trait WsSend: Clone {
	fn send<M>(&self, msg: M) -> Result<()>
	where
		M: Into<Message> + 'static;
}

/// WsSender wraps a ws::Sender -
/// also implements create a new WsWatchingClient (since it holds a ws::Sender itself, which is needed)
#[derive(Clone)]
pub struct WsSender {
	sender: Sender,
}

impl WsSend for WsSender {
	fn send<M>(&self, msg: M) -> Result<()>
	where
		M: Into<Message> + 'static,
	{
		self.sender.send(msg)
	}
}

impl CreateWatchingClient for WsSender {
	type Client = WsWatchingClient;

	fn create(&self, rpc_response: RpcResponse) -> Self::Client {
		WsWatchingClient { client: self.sender.clone(), response: rpc_response }
	}
}

impl WsSender {
	pub fn new(sender: Sender) -> Self {
		WsSender { sender }
	}
}

/// watching client
pub trait WatchingClient: WsSend + Send + Sync + Clone + 'static {
	fn close(&self) -> Result<()>;

	fn rpc_response(&self) -> &RpcResponse;

	fn update_response(&self, rpc_response: RpcResponse) -> Self;
}

/// Web-socket implementation of the watching client
#[derive(Clone)]
pub struct WsWatchingClient {
	client: Sender,
	response: RpcResponse,
}

impl WsWatchingClient {
	pub fn new(client: Sender, response: RpcResponse) -> Self {
		WsWatchingClient { client, response }
	}
}

impl WsSend for WsWatchingClient {
	fn send<M>(&self, msg: M) -> Result<()>
	where
		M: Into<Message>,
	{
		self.client.send(msg)
	}
}

impl WatchingClient for WsWatchingClient {
	fn close(&self) -> Result<()> {
		self.client.close(CloseCode::Normal)
	}

	fn rpc_response(&self) -> &RpcResponse {
		&self.response
	}

	fn update_response(&self, rpc_response: RpcResponse) -> Self {
		WsWatchingClient::new(self.client.clone(), rpc_response)
	}
}
