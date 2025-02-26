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

use hex_literal::hex;
use itp_types::parentchain::{Balance, BlockNumber, Hash};
use log::warn;

pub const PASEO_RELAY_GENESIS_HASH_HEX: [u8; 32] =
	hex!("77afd6190f1554ad45fd0d31aee62aacc33c6db0ea801129acb813f913e0764f");
pub const ASSET_HUB_PASEO_GENESIS_HASH_HEX: [u8; 32] =
	hex!("d6eec26135305a8ad257a20d003357284c8aa03d0bdb2b357ab0a22371e11ef2");
pub const INTEGRITEE_PASEO_GENESIS_HASH_HEX: [u8; 32] =
	hex!("1b69c462cd7dfea0e855c2008b66490cc8bbe90bc80b297ec0896a1c0941ce15");
pub const INTEGRITEE_KUSAMA_GENESIS_HASH_HEX: [u8; 32] =
	hex!("cdedc8eadbfa209d3f207bba541e57c3c58a667b05a2e1d1e86353c9000758da");
pub const INTEGRITEE_POLKADOT_GENESIS_HASH_HEX: [u8; 32] =
	hex!("e13e7af377c64e83f95e0d70d5e5c3c01d697a84538776c5b9bbe0e7d7b6034c");
pub const KUSAMA_RELAY_GENESIS_HASH_HEX: [u8; 32] =
	hex!("b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe");
pub const ASSET_HUB_KUSAMA_GENESIS_HASH_HEX: [u8; 32] =
	hex!("48239ef607d7928874027a43a67689209727dfb3d3dc5e5b03a39bdc2eda771a");
pub const POLKADOT_RELAY_GENESIS_HASH_HEX: [u8; 32] =
	hex!("91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3");
pub const ASSET_HUB_POLKADOT_GENESIS_HASH_HEX: [u8; 32] =
	hex!("68d56f15f85d3136970ec16946040bc1752654e906147f7e43e9d539d7c3de2f");

/// modify this for testing if necessary (brittle)
pub const LOCAL_TEST_GENESIS_HASH_HEX: [u8; 32] =
	hex!("6ca6d29ad6c4a200c4af356f74f03d6467dbc8a6e9ef225a2e672a990e1c7ead");
/// LOCAL ASSET_HUB_ROCOCO (brittle)
pub const ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX: [u8; 32] =
	hex!("af94f065f724b64ec40a7dd7ca3d25b3493d462f1e991b979e7683ae2a5da8d6");

pub struct MinimalChainSpec {}

impl MinimalChainSpec {
	pub fn decimals(genesis_hash: Hash) -> u8 {
		match genesis_hash.into() {
			PASEO_RELAY_GENESIS_HASH_HEX | ASSET_HUB_PASEO_GENESIS_HASH_HEX => 10,
			POLKADOT_RELAY_GENESIS_HASH_HEX | ASSET_HUB_POLKADOT_GENESIS_HASH_HEX => 10,
			KUSAMA_RELAY_GENESIS_HASH_HEX | ASSET_HUB_KUSAMA_GENESIS_HASH_HEX => 12,
			INTEGRITEE_PASEO_GENESIS_HASH_HEX
			| INTEGRITEE_KUSAMA_GENESIS_HASH_HEX
			| INTEGRITEE_POLKADOT_GENESIS_HASH_HEX => 12,
			LOCAL_TEST_GENESIS_HASH_HEX | ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX => 12,
			_ => {
				warn!(
					"parentchain spec for genesis 0x{:#x} unknown. defaulting to 12 decimals",
					genesis_hash
				);
				12
			},
		}
	}
	pub fn one_unit(genesis_hash: Hash) -> Balance {
		10u128.pow(Self::decimals(genesis_hash) as u32)
	}

	/// maintenance mode should be a temporary measure.
	/// If a problem can't be resolved within the time specified here, the shard should be retired to avoid loss of user funds
	pub fn maintenance_mode_duration_before_retirement(genesis_hash: Hash) -> BlockNumber {
		match genesis_hash.into() {
			PASEO_RELAY_GENESIS_HASH_HEX
			| ASSET_HUB_PASEO_GENESIS_HASH_HEX
			| INTEGRITEE_PASEO_GENESIS_HASH_HEX => 300, // 1h at 12s block time
			POLKADOT_RELAY_GENESIS_HASH_HEX | ASSET_HUB_POLKADOT_GENESIS_HASH_HEX => 216_000, // 30d for all production chains
			KUSAMA_RELAY_GENESIS_HASH_HEX | ASSET_HUB_KUSAMA_GENESIS_HASH_HEX => 216_000, // 30d for all production chains
			INTEGRITEE_KUSAMA_GENESIS_HASH_HEX | INTEGRITEE_POLKADOT_GENESIS_HASH_HEX => 216_000, // 30d for all production chains
			LOCAL_TEST_GENESIS_HASH_HEX | ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX => 20, // 10 min at 12s block time
			_ => 7200, // if undefined, leave 24h to react
		}
	}

	pub fn is_known_production_chain(genesis_hash: Hash) -> bool {
		matches!(
			genesis_hash.into(),
			POLKADOT_RELAY_GENESIS_HASH_HEX
				| ASSET_HUB_POLKADOT_GENESIS_HASH_HEX
				| KUSAMA_RELAY_GENESIS_HASH_HEX
				| ASSET_HUB_KUSAMA_GENESIS_HASH_HEX
				| INTEGRITEE_KUSAMA_GENESIS_HASH_HEX
				| INTEGRITEE_POLKADOT_GENESIS_HASH_HEX
		)
	}
}
