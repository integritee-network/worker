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
use codec::Error as CodecError;
use itp_api_client_types::InvalidMetadataError;
use serde_json::Error as JsonError;
use std::{boxed::Box, sync::mpsc::RecvError};
use thiserror;
use ws::Error as WsClientError;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("{0}")]
	Codec(#[from] CodecError),
	#[error("{0}")]
	SerdeJson(#[from] JsonError),
	#[error("Validateer returned the following error message: {0}")]
	Status(String),
	#[error("Websocket error: {0}")]
	WsClientError(#[from] WsClientError),
	#[error("Faulty channel: {0}")]
	MspcReceiver(#[from] RecvError),
	#[error("InvalidMetadata: {0:?}")]
	InvalidMetadata(InvalidMetadataError),
	#[error("Custom Error: {0}")]
	Custom(Box<dyn std::error::Error + Sync + Send + 'static>),
}

impl From<InvalidMetadataError> for Error {
	fn from(error: InvalidMetadataError) -> Self {
		Error::InvalidMetadata(error)
	}
}
