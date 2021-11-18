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

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

use ita_stf::hash::TrustedOperationOrHash;
use itp_types::{OpaqueCall, H256};
use std::vec::Vec;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use thiserror_sgx as thiserror;
}

pub mod error;
pub mod traits;

#[cfg(feature = "sgx")]
pub mod executor;

/// Execution status of a trusted operation
///
/// In case of success, it includes the operation hash, as well as
/// any extrinsic callbacks (e.g. unshield extrinsics) that need to be executed on-chain
#[derive(Clone, Debug)]
pub enum ExecutionStatus {
	Success(H256, Vec<OpaqueCall>),
	Failure,
}

impl ExecutionStatus {
	pub fn get_extrinsic_callbacks(&self) -> Vec<OpaqueCall> {
		match self {
			ExecutionStatus::Success(_, opaque_calls) => opaque_calls.clone(),
			_ => Vec::new(),
		}
	}

	pub fn get_executed_operation_hash(&self) -> Option<H256> {
		match self {
			ExecutionStatus::Success(operation_hash, _) => Some(*operation_hash),
			_ => None,
		}
	}
}

/// Information about an executed trusted operation
///
///
#[derive(Clone, Debug)]
pub struct ExecutedOperation {
	pub status: ExecutionStatus,
	pub trusted_operation_or_hash: TrustedOperationOrHash<H256>,
}

impl ExecutedOperation {
	/// constructor for a successfully executed trusted operation
	pub fn success(
		operation_hash: H256,
		trusted_operation_or_hash: TrustedOperationOrHash<H256>,
		extrinsic_call_backs: Vec<OpaqueCall>,
	) -> Self {
		ExecutedOperation {
			status: ExecutionStatus::Success(operation_hash, extrinsic_call_backs),
			trusted_operation_or_hash,
		}
	}

	/// constructor for a failed trusted operation execution
	pub fn failed(trusted_operation_or_hash: TrustedOperationOrHash<H256>) -> Self {
		ExecutedOperation { status: ExecutionStatus::Failure, trusted_operation_or_hash }
	}

	/// returns if the executed operation was a success
	pub fn is_success(&self) -> bool {
		matches!(self.status, ExecutionStatus::Success(_, _))
	}
}

/// Result of an execution on the STF
///
/// Contains multiple executed operations
#[derive(Clone, Debug)]
pub struct BatchExecutionResult {
	pub initial_state_hash: H256,
	pub executed_operations: Vec<ExecutedOperation>,
}

impl BatchExecutionResult {
	pub fn get_extrinsic_callbacks(&self) -> Vec<OpaqueCall> {
		self.executed_operations
			.iter()
			.flat_map(|e| e.status.get_extrinsic_callbacks())
			.collect()
	}

	pub fn get_executed_operation_hashes(&self) -> Vec<H256> {
		self.executed_operations
			.iter()
			.flat_map(|ec| ec.status.get_executed_operation_hash())
			.collect()
	}
}
