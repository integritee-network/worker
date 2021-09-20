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

use std::string::String;

/// REST client error
#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("HTTP client creation failed")]
	HttpClientError,

	#[error("Failed to parse final URL.")]
	UrlError,

	#[error("Failed to serialize struct to JSON (in POST): {0}")]
	SerializeParseError(serde_json::Error),

	#[error("Failed to deserialize data to struct (in GET or POST response: {0} {1}")]
	DeserializeParseError(serde_json::Error, String),

	#[error("Failed to make the outgoing request")]
	RequestError,

	#[error("HTTP header error: {0}")]
	HttpHeaderError(http::header::ToStrError),

	#[error(transparent)]
	HttpReqError(#[from] http_req::error::Error),

	#[error("Failed to perform IO operation: {0}")]
	IoError(std::io::Error),

	#[error("Server returned non-success status: {0}, details: {1}")]
	HttpError(u16, String),

	#[error("Request has timed out")]
	TimeoutError,

	#[error("Invalid parameter value")]
	InvalidValue,
}
