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

//! Transaction pool errors.

use sp_runtime::transaction_validity::{
	TransactionPriority as Priority
};

extern crate alloc;
use alloc::{
	boxed::Box,
	string::String,
};
use core::hash;
use derive_more::{Display, From};
/// Transaction pool result.
pub type Result<T> = sgx_tstd::result::Result<T, Error>;

/// Transaction pool error type.
#[derive(Debug, From, Display)]
#[allow(missing_docs)]
pub enum Error {
	#[display("Unknown transaction validity")]
	UnknownTransaction,

	#[display("Invalid transaction validity")]
	InvalidTransaction,

	/// Incorrect extrinsic format.

	/// The transaction validity returned no "provides" tag.
	///
	/// Such transactions are not accepted to the pool, since we use those tags
	/// to define identity of transactions (occupance of the same "slot").
	#[display("Transaction does not provide any tags, so the pool can't identify it")]
	NoTagsProvided,

	#[display("Transaction temporarily Banned")]
	TemporarilyBanned,

	#[display("Already imported")]
	AlreadyImported,
	
	#[display("Too low priority")]
	TooLowPriority(Priority),

	#[display("Transaction with cyclic dependency")]
	CycleDetected,

	#[display("Transaction couldn't enter the pool because of the limit")]
	ImmediatelyDropped,

	#[from(ignore)]
	#[display("{0}")]
	InvalidBlockId(String),

	#[display("The pool is not accepting future transactions")]
	RejectedFutureTransaction,

	#[display(fmt="Extrinsic verification error")]
	#[from(ignore)]
	Verification,
}

/// Transaction pool error conversion.
pub trait IntoPoolError: Send + Sized {
	/// Try to extract original `Error`
	///
	/// This implementation is optional and used only to
	/// provide more descriptive error messages for end users
	/// of RPC API.
	fn into_pool_error(self) -> sgx_tstd::result::Result<Error, Self> { Err(self) }
}

impl IntoPoolError for Error {
	fn into_pool_error(self) -> sgx_tstd::result::Result<Error, Self> { Ok(self) }
}
