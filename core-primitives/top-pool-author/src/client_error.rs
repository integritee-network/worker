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

//! Authoring RPC module client errors.

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use derive_more::{Display, From};
use jsonrpc_core as rpc_core;
use std::{boxed::Box, format};

/// Author RPC Result type.
pub type Result<T> = core::result::Result<T, Error>;

/// Author RPC errors.
#[derive(Debug, Display, From)]
pub enum Error {
	/// Client error.
	#[display(fmt = "Client error: {}", _0)]
	#[from(ignore)]
	Client(Box<dyn std::error::Error + Sync + Send + 'static>),
	/// TrustedOperation pool error,
	#[display(fmt = "TrustedOperation pool error: {}", _0)]
	Pool(itp_top_pool::error::Error),
	/// Verification error
	#[display(fmt = "Extrinsic verification error")]
	#[from(ignore)]
	Verification,
	/// Incorrect extrinsic format.
	#[display(fmt = "Invalid trusted call format")]
	BadFormat,
	// Incorrect enciphered trusted call format.
	#[display(fmt = "Invalid enciphered trusted call format")]
	BadFormatDecipher,
	/// Incorrect seed phrase.
	#[display(fmt = "Invalid seed phrase/SURI")]
	BadSeedPhrase,
	/// Key type ID has an unknown format.
	#[display(fmt = "Invalid key type ID format (should be of length four)")]
	BadKeyType,
	/// Key type ID has some unsupported crypto.
	#[display(fmt = "The crypto of key type ID is unknown")]
	UnsupportedKeyType,
	/// Some random issue with the key store. Shouldn't happen.
	#[display(fmt = "The key store is unavailable")]
	KeyStoreUnavailable,
	/// Invalid session keys encoding.
	#[display(fmt = "Session keys are not encoded correctly")]
	InvalidSessionKeys,
	/// Shard does not exist.
	#[display(fmt = "Shard does not exist")]
	InvalidShard,
	/// Unsupported trusted operation (in case we allow only certain types of operations, using filters)
	#[display(fmt = "Unsupported operation type")]
	UnsupportedOperation,
}

impl std::error::Error for Error {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Error::Client(ref err) => Some(&**err),
			//Error::Pool(ref err) => Some(err),
			//Error::Verification(ref err) => Some(&**err),
			_ => None,
		}
	}
}

/// Base code for all authorship errors.
const BASE_ERROR: i64 = 1000;
/// Extrinsic has an invalid format.
const BAD_FORMAT: i64 = BASE_ERROR + 1;
/// Error during operation verification in runtime.
const VERIFICATION_ERROR: i64 = BASE_ERROR + 2;

/// Pool rejected the operation as invalid
const POOL_INVALID_TX: i64 = BASE_ERROR + 10;
/// Cannot determine operation validity.
const POOL_UNKNOWN_VALIDITY: i64 = POOL_INVALID_TX + 1;
/// The operation is temporarily banned.
const POOL_TEMPORARILY_BANNED: i64 = POOL_INVALID_TX + 2;
/// The operation is already in the pool
const POOL_ALREADY_IMPORTED: i64 = POOL_INVALID_TX + 3;
/// TrustedOperation has too low priority to replace existing one in the pool.
const POOL_TOO_LOW_PRIORITY: i64 = POOL_INVALID_TX + 4;
/// Including this operation would cause a dependency cycle.
const POOL_CYCLE_DETECTED: i64 = POOL_INVALID_TX + 5;
/// The operation was not included to the pool because of the limits.
const POOL_IMMEDIATELY_DROPPED: i64 = POOL_INVALID_TX + 6;
/// The key type crypto is not known.
const UNSUPPORTED_KEY_TYPE: i64 = POOL_INVALID_TX + 7;

impl From<Error> for rpc_core::Error {
	fn from(e: Error) -> Self {
		use itp_top_pool::error::Error as PoolError;

		match e {
			Error::BadFormat => rpc_core::Error {
				code: rpc_core::ErrorCode::ServerError(BAD_FORMAT),
				message: "Trusted operation has invalid format".into(),
				data: None,
			},
			Error::BadFormatDecipher => rpc_core::Error {
				code: rpc_core::ErrorCode::ServerError(BAD_FORMAT),
				message: "Trusted operation could not be deciphered".into(),
				data: None,
			},
			Error::Verification => rpc_core::Error {
				code: rpc_core::ErrorCode::ServerError(VERIFICATION_ERROR),
				message: "Verification Error".into(),
				data: Some(format!("{:?}", e).into()),
			},
			Error::InvalidShard => rpc_core::Error {
				code: rpc_core::ErrorCode::ServerError(VERIFICATION_ERROR),
				message: "Shard does not exist".into(),
				data: Some(format!("{:?}", e).into()),
			},
			Error::Pool(PoolError::InvalidTrustedOperation) => rpc_core::Error {
				code: rpc_core::ErrorCode::ServerError(POOL_INVALID_TX),
				message: "Invalid Trusted Operation".into(),
				data: None,
			},
			Error::Pool(PoolError::UnknownTrustedOperation) => rpc_core::Error {
				code: rpc_core::ErrorCode::ServerError(POOL_UNKNOWN_VALIDITY),
				message: "Unknown Trusted Operation Validity".into(),
				data: None,
			},
			Error::Pool(PoolError::TemporarilyBanned) => rpc_core::Error {
				code: rpc_core::ErrorCode::ServerError(POOL_TEMPORARILY_BANNED),
				message: "Trusted Operation is temporarily banned".into(),
				data: None,
			},
			Error::Pool(PoolError::AlreadyImported) => rpc_core::Error {
				code: rpc_core::ErrorCode::ServerError(POOL_ALREADY_IMPORTED),
				message: "Trusted Operation Already Imported".into(),
				data: None,
			},
			Error::Pool(PoolError::TooLowPriority(new)) => rpc_core::Error {
				code: rpc_core::ErrorCode::ServerError(POOL_TOO_LOW_PRIORITY),
				message: format!("Priority is too low: {}", new),
				data: Some("The Trusted Operation has too low priority to replace another Trusted Operation already in the pool.".into()),
			},
			Error::Pool(PoolError::CycleDetected) => rpc_core::Error {
				code: rpc_core::ErrorCode::ServerError(POOL_CYCLE_DETECTED),
				message: "Cycle Detected".into(),
				data: None,
			},
			Error::Pool(PoolError::ImmediatelyDropped) => rpc_core::Error {
				code: rpc_core::ErrorCode::ServerError(POOL_IMMEDIATELY_DROPPED),
				message: "Immediately Dropped".into(),
				data: Some("The Trusted Operation couldn't enter the pool because of the limit".into()),
			},
			Error::UnsupportedKeyType => rpc_core::Error {
				code: rpc_core::ErrorCode::ServerError(UNSUPPORTED_KEY_TYPE),
				message: "Unknown key type crypto" .into(),
				data: Some(
					"The crypto for the given key type is unknown, please add the public key to the \
					request to insert the key successfully.".into()
				),
			},
			e => rpc_core::Error {
				code: rpc_core::ErrorCode::InternalError,
				message: "Unknown error occurred".into(),
				data: Some(format!("{:?}", e).into()),
			},
		}
	}
}
