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
#![cfg_attr(test, feature(assert_matches))]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

use codec::Encode;
use ita_stf::hash::TrustedOperationOrHash;
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_types::{OpaqueCall, H256};
use std::vec::Vec;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use thiserror_sgx as thiserror;
}

pub mod error;
pub mod getter_executor;
pub mod state_getter;
pub mod traits;

#[cfg(feature = "sgx")]
pub mod executor;

#[cfg(feature = "sgx")]
pub mod enclave_signer;

#[cfg(all(feature = "sgx", feature = "test"))]
pub mod executor_tests;

#[cfg(feature = "mocks")]
pub mod mocks;

/// Execution status of a trusted operation
///
/// In case of success, it includes the operation hash, as well as
/// any extrinsic callbacks (e.g. unshield extrinsics) that need to be executed on-chain
#[derive(Clone, Debug, PartialEq)]
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
#[derive(Clone, Debug, PartialEq)]
pub struct ExecutedOperation {
	pub status: ExecutionStatus,
	pub trusted_operation_or_hash: TrustedOperationOrHash<H256>,
}

impl ExecutedOperation {
	/// Constructor for a successfully executed trusted operation.
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

	/// Constructor for a failed trusted operation execution.
	pub fn failed(trusted_operation_or_hash: TrustedOperationOrHash<H256>) -> Self {
		ExecutedOperation { status: ExecutionStatus::Failure, trusted_operation_or_hash }
	}

	/// Returns true if the executed operation was a success.
	pub fn is_success(&self) -> bool {
		matches!(self.status, ExecutionStatus::Success(_, _))
	}
}

/// Result of an execution on the STF
///
/// Contains multiple executed operations
#[derive(Clone, Debug)]
pub struct BatchExecutionResult<Externalities: SgxExternalitiesTrait + Encode> {
	pub state_hash_before_execution: H256,
	pub executed_operations: Vec<ExecutedOperation>,
	pub state_after_execution: Externalities,
}

impl<Externalities> BatchExecutionResult<Externalities>
where
	Externalities: SgxExternalitiesTrait + Encode,
{
	pub fn get_extrinsic_callbacks(&self) -> Vec<OpaqueCall> {
		self.executed_operations
			.iter()
			.flat_map(|e| e.status.get_extrinsic_callbacks())
			.collect()
	}

	/// Returns all successfully exectued operation hashes.
	pub fn get_executed_operation_hashes(&self) -> Vec<H256> {
		self.executed_operations
			.iter()
			.flat_map(|ec| ec.status.get_executed_operation_hash())
			.collect()
	}

	/// Returns all operations that were not executed.
	pub fn get_failed_operations(&self) -> Vec<ExecutedOperation> {
		self.executed_operations
			.iter()
			.flat_map(|ec| match ec.is_success() {
				false => Some(ec.clone()),
				true => None,
			})
			.collect()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use itp_sgx_externalities::SgxExternalities;

	#[test]
	fn is_success_works() {
		let (success, _) = create_success_operation_from_u8(1);
		let failed = create_failed_operation_from_u8(7);

		assert!(success.is_success());
		assert!(!failed.is_success());
	}

	#[test]
	fn get_executed_operation_hashes_works() {
		let (success_one, hash_success_one) = create_success_operation_from_u8(1);
		let (success_two, hash_success_two) = create_success_operation_from_u8(3);
		let failed = create_failed_operation_from_u8(7);
		let result = batch_execution_result(vec![success_one, failed, success_two]);

		let success_operations = result.get_executed_operation_hashes();

		assert_eq!(success_operations.len(), 2);
		assert!(success_operations.contains(&hash_success_one));
		assert!(success_operations.contains(&hash_success_two));
	}

	#[test]
	fn get_failed_operations_works() {
		let failed_one = create_failed_operation_from_u8(1);
		let failed_two = create_failed_operation_from_u8(3);
		let (success, _) = create_success_operation_from_u8(10);
		let result = batch_execution_result(vec![failed_one.clone(), failed_two.clone(), success]);

		let failed_operations = result.get_failed_operations();

		assert_eq!(failed_operations.len(), 2);
		assert!(failed_operations.contains(&failed_one));
		assert!(failed_operations.contains(&failed_two));
	}

	fn batch_execution_result(
		executed_calls: Vec<ExecutedOperation>,
	) -> BatchExecutionResult<SgxExternalities> {
		BatchExecutionResult {
			executed_operations: executed_calls,
			state_hash_before_execution: H256::default(),
			state_after_execution: SgxExternalities::default(),
		}
	}

	fn create_failed_operation_from_u8(int: u8) -> ExecutedOperation {
		ExecutedOperation::failed(TrustedOperationOrHash::Hash(H256::from([int; 32])))
	}

	fn create_success_operation_from_u8(int: u8) -> (ExecutedOperation, H256) {
		let hash = H256::from([int; 32]);
		let opaque_call: Vec<OpaqueCall> = vec![OpaqueCall(vec![int; 10])];
		let operation =
			ExecutedOperation::success(hash, TrustedOperationOrHash::Hash(hash), opaque_call);
		(operation, hash)
	}
}
