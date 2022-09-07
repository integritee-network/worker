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

use crate::client_error::Error as ClientError;
use core::pin::Pin;
use derive_more::{Display, From};
use itp_top_pool::error::{Error as PoolError, IntoPoolError};
use jsonrpc_core as rpc;
use std::{boxed::Box, error, format, string::String};

/// State RPC Result type.
pub type Result<T> = core::result::Result<T, Error>;

/// State RPC future Result type.
pub type FutureResult<T, E> =
	Pin<Box<dyn rpc::futures::Future<Output = core::result::Result<T, E>> + Send>>;

/// State RPC errors.
#[derive(Debug, Display, From)]
pub enum Error {
	/// Client error.
	#[display(fmt = "Client error: {}", _0)]
	Client(Box<dyn error::Error + Send>),
	/// Provided block range couldn't be resolved to a list of blocks.
	#[display(fmt = "Cannot resolve a block range ['{:?}' ... '{:?}]. {}", from, to, details)]
	InvalidBlockRange {
		/// Beginning of the block range.
		from: String,
		/// End of the block range.
		to: String,
		/// Details of the error message.
		details: String,
	},
	/// Provided count exceeds maximum value.
	#[display(fmt = "count exceeds maximum value. value: {}, max: {}", value, max)]
	InvalidCount {
		/// Provided value
		value: u32,
		/// Maximum allowed value
		max: u32,
	},

	/// Wrapping of PoolError to RPC Error
	PoolError(PoolError),

	/// Wrapping of ClientError to RPC Error
	ClientError(ClientError),

	#[display(fmt = "Codec error: {}", _0)]
	CodecError(codec::Error),
}

impl error::Error for Error {
	fn source(&self) -> Option<&(dyn error::Error + 'static)> {
		match self {
			Error::Client(ref err) => Some(&**err),
			_ => None,
		}
	}
}

impl IntoPoolError for Error {
	fn into_pool_error(self) -> std::result::Result<PoolError, Self> {
		match self {
			Error::PoolError(e) => Ok(e),
			e => Err(e),
		}
	}
}

/// Base code for all state errors.
const BASE_ERROR: i64 = 4000;

impl From<Error> for rpc::Error {
	fn from(e: Error) -> Self {
		match e {
			Error::InvalidBlockRange { .. } => rpc::Error {
				code: rpc::ErrorCode::ServerError(BASE_ERROR + 1),
				message: format!("{}", e),
				data: None,
			},
			Error::InvalidCount { .. } => rpc::Error {
				code: rpc::ErrorCode::ServerError(BASE_ERROR + 2),
				message: format!("{}", e),
				data: None,
			},
			e => rpc::Error {
				code: rpc::ErrorCode::ServerError(BASE_ERROR + 4),
				message: format!("{}", e),
				data: None,
			},
		}
	}
}
