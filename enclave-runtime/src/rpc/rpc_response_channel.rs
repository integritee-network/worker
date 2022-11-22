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

use crate::initialization::global_components::GLOBAL_WEB_SOCKET_SERVER_COMPONENT;
use itc_direct_rpc_server::{response_channel::ResponseChannel, DirectRpcError};
use itc_tls_websocket_server::{ConnectionToken, WebSocketResponder};
use itp_component_container::ComponentGetter;
use std::string::String;

/// RPC response channel.
///
/// Uses the web-socket server to send an RPC response/update.
/// In case no server is available or running, the response will be discarded.
#[derive(Default)]
pub struct RpcResponseChannel;

impl ResponseChannel<ConnectionToken> for RpcResponseChannel {
	type Error = DirectRpcError;

	fn respond(&self, token: ConnectionToken, message: String) -> Result<(), Self::Error> {
		let web_socket_server = GLOBAL_WEB_SOCKET_SERVER_COMPONENT
			.get()
			.map_err(|e| DirectRpcError::Other(e.into()))?;
		web_socket_server.send_message(token, message).map_err(|e| e.into())
	}
}
