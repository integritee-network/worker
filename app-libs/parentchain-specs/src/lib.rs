/*
	Copyright 2021 Integritee AG

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
// chain specs which can't be derived from chain state trustlessly by the light client
// we hardcode them here so they can't be changed by an adversarial enclave operator

#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
use itp_types::parentchain::{Balance, Hash};
use log::warn;

const PASEO_RELAY_GENESIS_HASH_HEX: &str =
	"77afd6190f1554ad45fd0d31aee62aacc33c6db0ea801129acb813f913e0764f";
const INTEGRITEE_PASEO_GENESIS_HASH_HEX: &str =
	"1b69c462cd7dfea0e855c2008b66490cc8bbe90bc80b297ec0896a1c0941ce15";
const INTEGRITEE_KUSAMA_GENESIS_HASH_HEX: &str =
	"cdedc8eadbfa209d3f207bba541e57c3c58a667b05a2e1d1e86353c9000758da";

/// modify this for testing if necessary
const LOCAL_TEST_GENESIS_HASH_HEX: &str =
	"6ca6d29ad6c4a200c4af356f74f03d6467dbc8a6e9ef225a2e672a990e1c7ead";
pub struct MinimalChainSpec {}

impl MinimalChainSpec {
	pub fn decimals(genesis_hash: Hash) -> u8 {
		let genesis_hash_hex = hex::encode(genesis_hash);
		match genesis_hash_hex.as_ref() {
			PASEO_RELAY_GENESIS_HASH_HEX => 10,
			INTEGRITEE_PASEO_GENESIS_HASH_HEX | INTEGRITEE_KUSAMA_GENESIS_HASH_HEX => 12,
			LOCAL_TEST_GENESIS_HASH_HEX => 10,
			_ => {
				warn!(
					"parentchain spec for genesis {} unknown. defaulting to 12 decimals",
					genesis_hash_hex
				);
				12
			},
		}
	}
	pub fn one_unit(genesis_hash: Hash) -> Balance {
		10u128.pow(Self::decimals(genesis_hash) as u32)
	}
}
