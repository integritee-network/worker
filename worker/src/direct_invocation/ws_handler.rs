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

use crate::direct_invocation::{
	watch_list_service::WatchList,
	watching_client::{CreateWatchingClient, WatchingClient, WsSend, WsSender},
};
use codec::{Decode, Encode};
use log::*;
use sp_core::H256 as Hash;
use std::sync::Arc;
use substratee_enclave_api::direct_request::DirectRequest;
use substratee_worker_primitives::{DirectRequestStatus, RpcResponse, RpcReturnValue};
use ws::{CloseCode, Handler, Message, Result, Sender};

/// Trait for an abstract factory to create a handler instance
pub trait CreateWsHandler {
	type Handler: Handler;

	/// create a WS handler based on a sender
	fn create(&self, sender: Sender) -> Self::Handler;
}

/// WS handler factory implementation, requires the enclave ID and a watch_list facade
pub struct WsHandlerFactory<Enclave, Watch>
where
	Enclave: DirectRequest + Clone,
	Watch: WatchList<Client = <WsSender as CreateWatchingClient>::Client>,
{
	enclave_api: Arc<Enclave>,
	watch_list: Arc<Watch>,
}

impl<Enclave, Watch> WsHandlerFactory<Enclave, Watch>
where
	Enclave: DirectRequest + Clone,
	Watch: WatchList<Client = <WsSender as CreateWatchingClient>::Client>,
{
	pub fn new(enclave_api: Arc<Enclave>, watch_list: Arc<Watch>) -> Self {
		WsHandlerFactory { enclave_api, watch_list }
	}
}

impl<Enclave, Watch> CreateWsHandler for WsHandlerFactory<Enclave, Watch>
where
	Enclave: DirectRequest + Clone,
	Watch: WatchList<Client = <WsSender as CreateWatchingClient>::Client>,
{
	type Handler = WsHandler<WsSender, Enclave, Watch, <WsSender as CreateWatchingClient>::Client>;

	fn create(&self, sender: Sender) -> Self::Handler {
		WsHandler {
			sender: WsSender::new(sender),
			enclave_api: self.enclave_api.clone(),
			watch_list: self.watch_list.clone(),
		}
	}
}

/// WebSocket Handler implementation
pub struct WsHandler<Sender, Enclave, Watch, Client>
where
	Client: WatchingClient,
	Sender: WsSend + CreateWatchingClient<Client = Client>,
	Enclave: DirectRequest,
	Watch: WatchList<Client = Client>,
{
	sender: Sender,
	enclave_api: Arc<Enclave>,
	watch_list: Arc<Watch>,
}

impl<Sender, Enclave, Watch, Client> Handler for WsHandler<Sender, Enclave, Watch, Client>
where
	Client: WatchingClient,
	Sender: WsSend + CreateWatchingClient<Client = Client>,
	Enclave: DirectRequest,
	Watch: WatchList<Client = Client>,
{
	fn on_message(&mut self, msg: Message) -> Result<()> {
		if self.handle_direct_invocation_request(msg.to_string().as_str()).is_err() {
			error!("direct invocation call was not successful");
		}
		Ok(())
	}

	fn on_close(&mut self, code: CloseCode, reason: &str) {
		debug!("Direct invocation WebSocket closing for ({:?}) {}", code, reason);
	}
}

impl<Sender, Enclave, Watch, Client> WsHandler<Sender, Enclave, Watch, Client>
where
	Client: WatchingClient,
	Sender: WsSend + CreateWatchingClient<Client = Client>,
	Enclave: DirectRequest,
	Watch: WatchList<Client = Client>,
{
	fn handle_direct_invocation_request(&self, request_message: &str) -> Result<()> {
		info!("Got message '{}'. ", request_message);

		let msg: Vec<u8> = request_message.as_bytes().to_vec();

		let response = self
			.enclave_api
			.rpc(msg)
			.map_err(|e| ws::Error::new(ws::ErrorKind::Internal, format!("{:?}", e)))?;

		let decoded_response = String::from_utf8_lossy(&response).to_string();

		let full_rpc_response = serde_json::from_str(&decoded_response)
			.map_err(|e| ws::Error::new(ws::ErrorKind::Internal, format!("{:?}", e)))?;

		self.add_to_watch_list_if_requested(&full_rpc_response);

		self.sender.send(serde_json::to_string(&full_rpc_response).unwrap())
	}

	fn add_to_watch_list_if_requested(&self, full_rpc_response: &RpcResponse) {
		let result_of_rpc_response =
			match RpcReturnValue::decode(&mut full_rpc_response.result.as_slice()) {
				Ok(r) => r,
				Err(e) => {
					warn!(
						"failed to decode RpcReturnValue ({:?}), skip adding it to watch list",
						e
					);
					return
				},
			};

		if let DirectRequestStatus::TrustedOperationStatus(_) = result_of_rpc_response.status {
			if result_of_rpc_response.do_watch {
				// start watching the call with the specific hash
				if let Ok(hash) = Hash::decode(&mut result_of_rpc_response.value.as_slice()) {
					// create new key and value entries to store

					let updated_response = RpcResponse {
						result: result_of_rpc_response.encode(),
						jsonrpc: full_rpc_response.jsonrpc.clone(),
						id: full_rpc_response.id,
					};

					let new_client = self.sender.create(updated_response);

					self.watch_list.add_watching_client(hash, new_client);
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {

	use super::*;
	use crate::{
		direct_invocation::{
			watch_list_service::WatchListService, watching_client::WatchingClient,
		},
		tests::direct_request_mock::DirectRequestMock,
	};
	use mockall::mock;
	use ws::Result;

	mock! {
		WatchingClient{}
		impl WsSend for WatchingClient {
			fn send<M>(&self, _msg: M) -> Result<()> where M: 'static
			{
				Ok(())
			}
		}

		impl WatchingClient for WatchingClient {
			fn close(&self) -> Result<()> {
				Ok(())
			}

			fn rpc_response(&self) -> &RpcResponse {
				&RpcResponse {
					jsonrpc: String::new(),
					result: Vec::<u8>::new(),
					id: 1u32,
				}
			}

			fn update_response(&self, rpc_response: RpcResponse) -> Self {
				self.clone()
			}
		}

		impl Clone for WatchingClient {
			fn clone(&self) -> Self {
				WatchingClient{}
			}
		}
	}

	mock! {
		Sender{}
		impl CreateWatchingClient for Sender {
			type Client = MockWatchingClient;

			fn create(&self, _rpc_response: RpcResponse) -> MockWatchingClient {
				MockWatchingClient
			}
		}
		impl WsSend for Sender {
			fn send<M>(&self, _msg: M) -> Result<()> where M: 'static
			{
				Ok(())
			}
		}
		impl Clone for Sender {
			fn clone(&self) -> Self {
				Sender{}
			}
		}
	}

	#[test]
	fn given_request_when_response_cannot_be_decoded_then_do_not_add_to_watch_list() {
		let watch_list = Arc::new(WatchListService::<MockWatchingClient>::new());
		let enclave_api = Arc::new(DirectRequestMock);
		let ws_sender = MockSender::new();

		let ws_handler =
			WsHandler { sender: ws_sender, watch_list: watch_list.clone(), enclave_api };

		let invalid_response =
			RpcResponse { result: vec![1u8, 2u8, 3u8], id: 1u32, jsonrpc: String::new() };

		ws_handler.add_to_watch_list_if_requested(&invalid_response);

		assert_eq!(0, watch_list.number_of_elements());
	}
}
