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
	connection_repository::ConnectionRepositoryControl, error::WebSocketResult, ConnectionId,
	WebSocketConnection, WebSocketHandler,
};
use log::*;
use std::{marker::PhantomData, sync::Arc};
use tungstenite::Message;

/// Triggers the processing of all active websocket connections.
pub trait ProcessWebSocketConnections {
	fn process_connections(&self) -> WebSocketResult<()>;
}

pub struct ConnectionProcessor<Connection, ConnectionRepository, MessageHandler> {
	repository: Arc<ConnectionRepository>,
	handler: Arc<MessageHandler>,
	phantom_data: PhantomData<Connection>,
}

impl<Connection, ConnectionRepository, MessageHandler>
	ConnectionProcessor<Connection, ConnectionRepository, MessageHandler>
where
	Connection: WebSocketConnection,
	ConnectionRepository: ConnectionRepositoryControl<Connection>,
	MessageHandler: WebSocketHandler,
{
	pub fn send_response(
		&self,
		connection_id: ConnectionId,
		response: String,
	) -> WebSocketResult<()> {
		self.repository
			.execute_on_connection(connection_id, move |c| c.send_update(response))
	}

	fn process_single_connection(
		&self,
		connection: &mut Connection,
	) -> WebSocketResult<ConnectionProcessingResult> {
		//connection.write_pending()?;

		let processing_result = match connection.read_message()? {
			Message::Text(s) => {
				debug!("Received test message");
				if let Some(response_string) = self.handler.handle_message(connection.id(), s)? {
					connection.send_update(response_string)?;
				}
				ConnectionProcessingResult::MessageProcessed
			},
			Message::Binary(_) => {
				debug!("Received binary message");
				ConnectionProcessingResult::UnsupportedMessageType
			},
			Message::Ping(_) => {
				debug!("Received ping message");
				ConnectionProcessingResult::HeartBeat
			},
			Message::Pong(_) => {
				debug!("Received pong message");
				ConnectionProcessingResult::HeartBeat
			},
			Message::Close(_) => {
				debug!("Connection is closed");
				ConnectionProcessingResult::ConnectionClosed(connection.id())
			},
		};

		Ok(processing_result)
	}
}

impl<Connection, ConnectionRepository, MessageHandler> ProcessWebSocketConnections
	for ConnectionProcessor<Connection, ConnectionRepository, MessageHandler>
where
	Connection: WebSocketConnection,
	ConnectionRepository: ConnectionRepositoryControl<Connection>,
	MessageHandler: WebSocketHandler,
{
	fn process_connections(&self) -> WebSocketResult<()> {
		self.repository.move_new_connections_to_active()?;

		let processing_results = self
			.repository
			.process_active_connections(|c| self.process_single_connection(c))?;

		let closed_connections: Vec<ConnectionId> = processing_results
			.iter()
			.flat_map(|r| match r {
				ConnectionProcessingResult::ConnectionClosed(id) => Some(*id),
				_ => None,
			})
			.collect();

		self.repository.remove_connections(closed_connections.as_slice())?;

		Ok(())
	}
}

enum ConnectionProcessingResult {
	ConnectionClosed(ConnectionId),
	UnsupportedMessageType,
	MessageProcessed,
	HeartBeat,
}
