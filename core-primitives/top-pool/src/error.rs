// This file is part of Substrate.

// Copyright (C) 2018-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! TrustedOperation pool errors.

use derive_more::{Display, From};
use sp_runtime::transaction_validity::TransactionPriority as Priority;
use std::string::String;

/// TrustedOperation pool result.
pub type Result<T> = std::result::Result<T, Error>;

/// TrustedOperation pool error type.
#[derive(Debug, From, Display)]
#[allow(missing_docs)]
pub enum Error {
	#[display(fmt = "Unknown trusted operation")]
	UnknownTrustedOperation,

	#[display(fmt = "Invalid trusted operation")]
	InvalidTrustedOperation,

	/// Incorrect extrinsic format.

	/// The operation validity returned no "provides" tag.
	///
	/// Such operations are not accepted to the pool, since we use those tags
	/// to define identity of operations (occupance of the same "slot").
	#[display(fmt = "Trusted Operation does not provide any tags, so the pool can't identify it")]
	NoTagsProvided,

	#[display(fmt = "Trusted Operation temporarily Banned")]
	TemporarilyBanned,

	#[display(fmt = "Already imported")]
	AlreadyImported,

	#[display(fmt = "Too low priority")]
	TooLowPriority(Priority),

	#[display(fmt = "TrustedOperation with cyclic dependency")]
	CycleDetected,

	#[display(fmt = "TrustedOperation couldn't enter the pool because of the limit")]
	ImmediatelyDropped,

	#[from(ignore)]
	#[display(fmt = "Invalid Block")]
	InvalidBlockId(String),

	#[display(fmt = "The pool is not accepting future trusted operations")]
	RejectedFutureTrustedOperation,

	#[display(fmt = "Extrinsic verification error")]
	#[from(ignore)]
	Verification,

	#[display(fmt = "Failed to send result of trusted operation to RPC client")]
	FailedToSendUpdateToRpcClient(String),

	#[display(fmt = "Failed to unlock pool (mutex)")]
	UnlockError,
}

/// TrustedOperation pool error conversion.
pub trait IntoPoolError: Send + Sized {
	/// Try to extract original `Error`
	///
	/// This implementation is optional and used only to
	/// provide more descriptive error messages for end users
	/// of RPC API.
	fn into_pool_error(self) -> std::result::Result<Error, Self> {
		Err(self)
	}
}

impl IntoPoolError for Error {
	fn into_pool_error(self) -> std::result::Result<Error, Self> {
		Ok(self)
	}
}
