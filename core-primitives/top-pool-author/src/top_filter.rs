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

#[cfg(test)]
pub mod tests {

	use super::*;
	use codec::Encode;
	use ita_stf::{Getter, KeyPair, TrustedCall, TrustedGetter};
	use itp_types::ShardIdentifier;
	use sp_core::{ed25519, Pair};
	use sp_runtime::traits::{BlakeTwo256, Hash};
	use std::string::{String, ToString};

	type Seed = [u8; 32];
	const TEST_SEED: Seed = *b"12345678901234567890123456789012";

	#[test]
	pub fn filter_returns_none_if_values_is_filtered_out() {
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
	pub fn getters_only_filter_allows_trusted_getters() {
		let account = test_account();

		let getter = TrustedGetter::free_balance(account.public().into());
		let trusted_getter_signed = Getter::trusted(getter.sign(&KeyPair::Ed25519(account)));
		let trusted_operation = TrustedOperation::from(trusted_getter_signed);

		let filter = GettersOnlyFilter;

		assert!(filter.filter(&trusted_operation));
	}

	#[test]
	pub fn getters_only_filter_denies_trusted_calls() {
		let account = test_account();
		let call =
			TrustedCall::balance_shield(account.public().into(), account.public().into(), 12u128);
		let call_signed = call.sign(&KeyPair::Ed25519(account), 0, &mr_enclave(), &shard_id());
		let trusted_operation = TrustedOperation::from(call_signed);

		let filter = GettersOnlyFilter;

		assert!(!filter.filter(&trusted_operation));
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
