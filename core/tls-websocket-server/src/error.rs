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

use crate::ConnectionId;
use std::{boxed::Box, io::Error as IoError, net::AddrParseError, string::String};

pub type WebSocketResult<T> = Result<T, WebSocketError>;

/// General web-socket error type
#[derive(Debug, thiserror::Error)]
pub enum WebSocketError {
	#[error("Invalid certificate error: {0}")]
	InvalidCertificate(String),
	#[error("Invalid private key error: {0}")]
	InvalidPrivateKey(String),
	#[error("Invalid web-socket address error: {0}")]
	InvalidWsAddress(AddrParseError),
	#[error("TCP bind error: {0}")]
	TcpBindError(IoError),
	#[error("Web-socket hand shake error")]
	HandShakeError,
	#[error("{0} is not a valid and active web-socket connection id")]
	InvalidConnection(ConnectionId),
	#[error("Web-socket connection already closed error")]
	ConnectionClosed,
	#[error("Web-socket connection has not yet been established")]
	ConnectionNotYetEstablished,
	#[error("Web-socket write error: {0}")]
	SocketWriteError(String),
	#[error("Lock poisoning")]
	LockPoisoning,
	#[error("Failed to receive server signal message: {0}")]
	MioReceiveError(#[from] std::sync::mpsc::TryRecvError),
	#[error("I/O error: {0}")]
	IoError(#[from] std::io::Error),
	#[error("General web-socket error: {0}")]
	Other(Box<dyn std::error::Error + Sync + Send + 'static>),
}
