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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use log::*;
use mio::net::TcpStream;
use rustls::ServerSession;
use tungstenite::{
	accept,
	handshake::{server::NoCallback, MidHandshake},
	HandshakeError, ServerHandshake, WebSocket,
};

pub(crate) type RustlsStream = rustls::StreamOwned<ServerSession, TcpStream>;
pub(crate) type RustlsServerHandshake = ServerHandshake<RustlsStream, NoCallback>;
pub(crate) type RustlsMidHandshake = MidHandshake<RustlsServerHandshake>;
pub(crate) type RustlsWebSocket = WebSocket<RustlsStream>;

/// Internal TLS stream state. From pure TLS stream, to web-socket handshake and established WS.
pub(crate) enum StreamState {
	Invalid,
	TlsStream(RustlsStream),
	WebSocketHandshake(RustlsMidHandshake),
	EstablishedWebsocket(RustlsWebSocket),
}

impl Default for StreamState {
	fn default() -> Self {
		Self::Invalid
	}
}

impl StreamState {
	pub(crate) fn from_stream(stream: RustlsStream) -> Self {
		StreamState::TlsStream(stream)
	}

	pub(crate) fn is_invalid(&self) -> bool {
		matches!(self, StreamState::Invalid)
	}

	pub(crate) fn internal_stream(&self) -> Option<&RustlsStream> {
		match self {
			StreamState::TlsStream(s) => Some(s),
			StreamState::WebSocketHandshake(h) => Some(h.get_ref().get_ref()),
			StreamState::EstablishedWebsocket(ws) => Some(ws.get_ref()),
			StreamState::Invalid => None,
		}
	}

	pub(crate) fn internal_stream_mut(&mut self) -> Option<&mut RustlsStream> {
		match self {
			StreamState::TlsStream(s) => Some(s),
			StreamState::WebSocketHandshake(h) => Some(h.get_mut().get_mut()),
			StreamState::EstablishedWebsocket(ws) => Some(ws.get_mut()),
			StreamState::Invalid => None,
		}
	}

	pub(crate) fn attempt_handshake(self) -> Self {
		match self {
			// We have the bare TLS stream only, attempt to do a web-socket handshake.
			StreamState::TlsStream(tls_stream) => Self::from_handshake_result(accept(tls_stream)),
			// We already have an on-going handshake, attempt another try.
			StreamState::WebSocketHandshake(hs) => Self::from_handshake_result(hs.handshake()),
			_ => self,
		}
	}

	fn from_handshake_result(
		handshake_result: Result<RustlsWebSocket, HandshakeError<RustlsServerHandshake>>,
	) -> Self {
		match handshake_result {
			Ok(ws) => Self::EstablishedWebsocket(ws),
			Err(e) => match e {
				// I/O would block our handshake attempt. Need to re-try.
				HandshakeError::Interrupted(mhs) => {
					info!("Web-socket handshake interrupted");
					Self::WebSocketHandshake(mhs)
				},
				HandshakeError::Failure(e) => {
					error!("Web-socket handshake failed: {:?}", e);
					Self::Invalid
				},
			},
		}
	}
}
