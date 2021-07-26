// This file is part of Substrate.

// Copyright (C) 2017-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! State RPC errors.

use jsonrpc_core as rpc;

use std::error;

pub extern crate alloc;
use alloc::{boxed::Box, string::String};

use core::pin::Pin;

use crate::top_pool::error::{Error as PoolError, IntoPoolError};

use crate::rpc::author::client_error::Error as ClientError;

use derive_more::{Display, From};

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
