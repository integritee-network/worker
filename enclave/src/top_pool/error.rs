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

use sp_runtime::transaction_validity::TransactionPriority as Priority;

extern crate alloc;
use alloc::string::String;

use derive_more::{Display, From};
/// TrustedOperation pool result.
pub type Result<T> = sgx_tstd::result::Result<T, Error>;

/// TrustedOperation pool error type.
#[derive(Debug, From, Display)]
#[allow(missing_docs)]
pub enum Error {
    #[display("Unknown trusted operation validity")]
    UnknownTrustedOperation,

    #[display("Invalid trusted operation validity")]
    InvalidTrustedOperation,

    /// Incorrect extrinsic format.

    /// The operation validity returned no "provides" tag.
    ///
    /// Such transactions are not accepted to the pool, since we use those tags
    /// to define identity of transactions (occupance of the same "slot").
    #[display("Trusted Operation does not provide any tags, so the pool can't identify it")]
    NoTagsProvided,

    #[display("Trusted Operation temporarily Banned")]
    TemporarilyBanned,

    #[display("Already imported")]
    AlreadyImported,

    #[display("Too low priority")]
    TooLowPriority(Priority),

    #[display("TrustedOperation with cyclic dependency")]
    CycleDetected,

    #[display("TrustedOperation couldn't enter the pool because of the limit")]
    ImmediatelyDropped,

    #[from(ignore)]
    #[display("{0}")]
    InvalidBlockId(String),

    #[display("The pool is not accepting future trusted operations")]
    RejectedFutureTrustedOperation,

    #[display(fmt = "Extrinsic verification error")]
    #[from(ignore)]
    Verification,
}

/// TrustedOperation pool error conversion.
pub trait IntoPoolError: Send + Sized {
    /// Try to extract original `Error`
    ///
    /// This implementation is optional and used only to
    /// provide more descriptive error messages for end users
    /// of RPC API.
    fn into_pool_error(self) -> sgx_tstd::result::Result<Error, Self> {
        Err(self)
    }
}

impl IntoPoolError for Error {
    fn into_pool_error(self) -> sgx_tstd::result::Result<Error, Self> {
        Ok(self)
    }
}
