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

use ita_stf::TrustedOperation;

/// Trait for filtering values
///
/// Returns `Some` if a value should be included and `None` if discarded
pub trait Filter {
	type Value;

	fn filter(&self, value: &Self::Value) -> bool;
}

/// Filter for calls only (no getters).
pub struct CallsOnlyFilter;

impl Filter for CallsOnlyFilter {
	type Value = TrustedOperation;

	fn filter(&self, value: &Self::Value) -> bool {
		matches!(value, TrustedOperation::direct_call(_))
			|| matches!(value, TrustedOperation::indirect_call(_))
	}
}

/// Filter that allows all TOPs (i.e. not filter at all)
pub struct AllowAllTopsFilter;

impl Filter for AllowAllTopsFilter {
	type Value = TrustedOperation;

	fn filter(&self, _value: &Self::Value) -> bool {
		true
	}
}

/// Filter that allows only trusted getters
pub struct GettersOnlyFilter;

impl Filter for GettersOnlyFilter {
	type Value = TrustedOperation;

	fn filter(&self, value: &Self::Value) -> bool {
		matches!(value, TrustedOperation::get(_))
	}
}

/// Filter for indirect calls only (no getters, no direct calls).
pub struct IndirectCallsOnlyFilter;

impl Filter for IndirectCallsOnlyFilter {
	type Value = TrustedOperation;

	fn filter(&self, value: &Self::Value) -> bool {
		matches!(value, TrustedOperation::indirect_call(_))
	}
}

/// Filter that allows no direct calls, only indirect and getters.
pub struct NoDirectCallsFilter;

impl Filter for NoDirectCallsFilter {
	type Value = TrustedOperation;

	fn filter(&self, value: &Self::Value) -> bool {
		!matches!(value, TrustedOperation::direct_call(_))
	}
}

/// Filter to deny all trusted operations.
pub struct DenyAllFilter;

impl Filter for DenyAllFilter {
	type Value = TrustedOperation;

	fn filter(&self, _value: &Self::Value) -> bool {
		false
	}
}

#[cfg(test)]
mod tests {

	use super::*;
	use codec::Encode;
	use ita_stf::{Getter, TrustedCall, TrustedCallSigned, TrustedGetter};
	use itp_stf_primitives::types::KeyPair;
	use itp_types::ShardIdentifier;
	use sp_core::{ed25519, Pair};
	use sp_runtime::traits::{BlakeTwo256, Hash};
	use std::{
		boxed::Box,
		string::{String, ToString},
	};

	type Seed = [u8; 32];
	const TEST_SEED: Seed = *b"12345678901234567890123456789012";

	#[test]
	fn filter_returns_none_if_values_is_filtered_out() {
		struct WorldFilter;
		impl Filter for WorldFilter {
			type Value = String;

			fn filter(&self, value: &Self::Value) -> bool {
				if value.eq(&String::from("world")) {
					return true
				}
				false
			}
		}

		let filter = WorldFilter;

		assert!(!filter.filter(&"hello".to_string()));
		assert!(filter.filter(&"world".to_string()));
	}

	#[test]
	fn allow_all_tops_filter_works() {
		let filter = AllowAllTopsFilter;

		assert!(filter.filter(&trusted_getter()));
		assert!(filter.filter(&trusted_indirect_call()));
		assert!(filter.filter(&trusted_direct_call()));
	}

	#[test]
	fn getters_only_filter_works() {
		let filter = GettersOnlyFilter;

		assert!(filter.filter(&trusted_getter()));
		assert!(!filter.filter(&trusted_indirect_call()));
		assert!(!filter.filter(&trusted_direct_call()));
	}

	#[test]
	fn no_direct_calls_filter_works() {
		let filter = NoDirectCallsFilter;

		assert!(!filter.filter(&trusted_direct_call()));
		assert!(filter.filter(&trusted_indirect_call()));
		assert!(filter.filter(&trusted_getter()));
	}

	#[test]
	fn indirect_calls_only_filter_works() {
		let filter = IndirectCallsOnlyFilter;

		assert!(!filter.filter(&trusted_direct_call()));
		assert!(filter.filter(&trusted_indirect_call()));
		assert!(!filter.filter(&trusted_getter()));
	}

	#[test]
	fn calls_only_filter_works() {
		let filter = CallsOnlyFilter;

		assert!(filter.filter(&trusted_direct_call()));
		assert!(filter.filter(&trusted_indirect_call()));
		assert!(!filter.filter(&trusted_getter()));
	}

	fn trusted_direct_call() -> TrustedOperation {
		TrustedOperation::direct_call(trusted_call_signed())
	}

	fn trusted_indirect_call() -> TrustedOperation {
		TrustedOperation::indirect_call(trusted_call_signed())
	}

	fn trusted_getter() -> TrustedOperation {
		let account = test_account();
		let getter = TrustedGetter::free_balance(account.public().into());
		let trusted_getter_signed =
			Getter::trusted(getter.sign(&KeyPair::Ed25519(Box::new(account))));
		TrustedOperation::from(trusted_getter_signed)
	}

	fn trusted_call_signed() -> TrustedCallSigned {
		let account = test_account();
		let call =
			TrustedCall::balance_shield(account.public().into(), account.public().into(), 12u128);
		call.sign(&KeyPair::Ed25519(Box::new(account)), 0, &mr_enclave(), &shard_id())
	}

	fn test_account() -> ed25519::Pair {
		ed25519::Pair::from_seed(&TEST_SEED)
	}

	fn shard_id() -> ShardIdentifier {
		BlakeTwo256::hash(vec![1u8, 2u8, 3u8].as_slice().encode().as_slice())
	}

	fn mr_enclave() -> [u8; 32] {
		[1u8; 32]
	}
}
