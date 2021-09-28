// This file is part of Substrate.

// Copyright (C) 2017-2021 Parity Technologies (UK) Ltd.
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

//! Error types in sidechain Consensus

use its_primitives::types::block::BlockHash;
use std::{
	boxed::Box,
	error,
	string::{String, ToString},
	vec::Vec,
};

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub use thiserror_sgx as thiserror;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
	#[error("Unable to create block proposal.")]
	CannotPropose,
	#[error("Message sender {0} is not a valid authority")]
	InvalidAuthority(String),
	#[error("Could not get authorities: {0:?}.")]
	CouldNotGetAuthorities(String),
	#[error(transparent)]
	Other(#[from] Box<dyn error::Error + Sync + Send + 'static>),
	#[error("Chain lookup failed: {0}")]
	ChainLookup(String),
	#[error("Failed to sign using key: {0:?}. Reason: {1}")]
	CannotSign(Vec<u8>, String),
	#[error("Bad parentchain block (Hash={0}). Reason: {1}")]
	BadParentchainBlock(BlockHash, String),
	#[error("Bad parentchain block (Hash={0}). Reason: {1}")]
	BadSidechainBlock(BlockHash, String),
}

impl core::convert::From<std::io::Error> for Error {
	fn from(e: std::io::Error) -> Self {
		Self::Other(e.into())
	}
}

impl core::convert::From<codec::Error> for Error {
	fn from(e: codec::Error) -> Self {
		Self::Other(e.to_string().into())
	}
}
