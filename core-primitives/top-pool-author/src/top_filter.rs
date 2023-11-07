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

use codec::{Encode, EncodeAppend};
use core::{fmt::Debug, marker::PhantomData};
use itp_stf_primitives::types::TrustedOperation as StfTrustedOperation;

/// Trait for filtering values
///
/// Returns `Some` if a value should be included and `None` if discarded
pub trait Filter {
	type Value;

	fn filter(&self, value: &Self::Value) -> bool;
}

/// Filter for calls only (no getters).
pub struct CallsOnlyFilter<TCS, G> {
	_phantom: PhantomData<(TCS, G)>,
}

impl<TCS, G> Filter for CallsOnlyFilter<TCS, G>
where
	TCS: Encode + Debug,
	G: Encode + Debug,
{
	type Value = StfTrustedOperation<TCS, G>;

	fn filter(&self, value: &Self::Value) -> bool {
		matches!(value, Self::Value::direct_call(_))
			|| matches!(value, Self::Value::indirect_call(_))
	}
}

/// Filter that allows all TOPs (i.e. not filter at all)
pub struct AllowAllTopsFilter<TCS, G> {
	_phantom: PhantomData<(TCS, G)>,
}

impl<TCS, G> Filter for AllowAllTopsFilter<TCS, G>
where
	TCS: Encode + Debug,
	G: Encode + Debug,
{
	type Value = StfTrustedOperation<TCS, G>;

	fn filter(&self, _value: &Self::Value) -> bool {
		true
	}
}

/// Filter that allows only trusted getters
pub struct GettersOnlyFilter<TCS, G> {
	_phantom: PhantomData<(TCS, G)>,
}

impl<TCS, G> Filter for GettersOnlyFilter<TCS, G>
where
	TCS: Encode + Debug,
	G: Encode + Debug,
{
	type Value = StfTrustedOperation<TCS, G>;

	fn filter(&self, value: &Self::Value) -> bool {
		matches!(value, Self::Value::get(_))
	}
}

/// Filter for indirect calls only (no getters, no direct calls).
pub struct IndirectCallsOnlyFilter<TCS, G> {
	_phantom: PhantomData<(TCS, G)>,
}

impl<TCS, G> Filter for IndirectCallsOnlyFilter<TCS, G>
where
	TCS: Encode + Debug,
	G: Encode + Debug,
{
	type Value = StfTrustedOperation<TCS, G>;

	fn filter(&self, value: &Self::Value) -> bool {
		matches!(value, Self::Value::indirect_call(_))
	}
}

/// Filter that allows no direct calls, only indirect and getters.
pub struct NoDirectCallsFilter<TCS, G> {
	_phantom: PhantomData<(TCS, G)>,
}

impl<TCS, G> Filter for NoDirectCallsFilter<TCS, G>
where
	TCS: Encode + Debug,
	G: Encode + Debug,
{
	type Value = StfTrustedOperation<TCS, G>;

	fn filter(&self, value: &Self::Value) -> bool {
		!matches!(value, Self::Value::direct_call(_))
	}
}

/// Filter to deny all trusted operations.
pub struct DenyAllFilter<TCS, G> {
	_phantom: PhantomData<(TCS, G)>,
}

impl<TCS, G> Filter for DenyAllFilter<TCS, G>
where
	TCS: Encode + Debug,
	G: Encode + Debug,
{
	type Value = StfTrustedOperation<TCS, G>;

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

	type TrustedOperationMock = StfTrustedOperation<u8, u8>;

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

	fn trusted_direct_call() -> TrustedOperationMock {
		TrustedOperationMock::direct_call(0)
	}

	fn trusted_indirect_call() -> TrustedOperationMock {
		TrustedOperationMock::indirect_call(0)
	}

	fn trusted_getter() -> TrustedOperationMock {
		TrustedOperationMock::get(0)
	}
}
