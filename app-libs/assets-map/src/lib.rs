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

// Explicit mapping between AssetId on L1 and L2
// All supported assets will be sufficient and eligible to pay fees for own scope

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use alloc::{sync::Arc, vec, vec::Vec};
use codec::{Decode, Encode, MaxEncodedLen};
use hex_literal::hex;
use ita_parentchain_specs::{
	ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX, ASSET_HUB_PASEO_GENESIS_HASH_HEX,
	ASSET_HUB_POLKADOT_GENESIS_HASH_HEX,
};
use itp_types::{
	parentchain::{Hash, ParentchainAssetIdNative},
	xcm::{
		Junction::{AccountKey20, GlobalConsensus},
		Junctions::{X1, X2},
		Location,
		NetworkId::Ethereum,
	},
	Balance,
};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};

#[derive(
	Decode,
	Encode,
	Clone,
	Copy,
	PartialEq,
	Eq,
	Debug,
	Serialize,
	Deserialize,
	TypeInfo,
	MaxEncodedLen,
)]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum AssetId {
	// Tether tokens
	/// USDT Tether, minted natively
	USDT = 10,
	/// USDT Tether, minted on Ethereum
	USDT_E = 11,

	// Circle tokens
	/// USDC Circle, minted natively
	USDC = 20,
	/// USDC Circle, minted on Ethereum
	USDC_E = 21,
	/// EURC Circle, minted on Ethereum
	EURC_E = 23,

	// protocol-issued tokens, wrapped or not
	/// Ethereum ETH,
	ETH = 30,
	/// wrapped ETH ERC20
	WETH = 31,
	/// Bitcoin. just reserving the index. no bridge exists yet
	BTC = 36,
	/// ethereum-wrapped Bitcoin
	WBTC_E = 37,
}

const USDC_E_MAINNET_CONTRACT_ADDRESS: [u8; 20] = hex!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
const EURC_E_MAINNET_CONTRACT_ADDRESS: [u8; 20] = hex!("1abaea1f7c830bd89acc67ec4af516284b1bc33c");
const USDT_E_MAINNET_CONTRACT_ADDRESS: [u8; 20] = hex!("dac17f958d2ee523a2206206994597c13d831ec7");
const WETH_SEPOLIA_CONTRACT_ADDRESS: [u8; 20] = hex!("fff9976782d46cc05630d1f6ebab18b2324d6b14");
const WBTC_E_MAINNET_CONTRACT_ADDRESS: [u8; 20] = hex!("2260fac5e5542a773aa44fbcfedf7c193bc2c599");

/// The AssetId type we use on L2 to map all possible locations/instances
/// This type must contain unique definitions for any token we may want to shield on any shielding target
/// The decision, which types are to be supported by which shielding target happens in `is_shieldable`.
#[cfg(feature = "std")]
impl std::fmt::Display for AssetId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			AssetId::USDT => write!(f, "USDT"),
			AssetId::USDT_E => write!(f, "USDT.e"),
			AssetId::USDC => write!(f, "USDC"),
			AssetId::USDC_E => write!(f, "USDC.e"),
			AssetId::EURC_E => write!(f, "EURC.e"),
			AssetId::ETH => write!(f, "ETH"),
			AssetId::WETH => write!(f, "WETH"),
			AssetId::BTC => write!(f, "BTC"),
			AssetId::WBTC_E => write!(f, "WBTC.e"),
		}
	}
}

#[cfg(feature = "std")]
impl TryFrom<&str> for AssetId {
	type Error = ();

	fn try_from(symbol: &str) -> Result<Self, Self::Error> {
		match symbol {
			"USDT" => Ok(AssetId::USDT),
			"USDT.e" => Ok(AssetId::USDT_E),
			"USDC" => Ok(AssetId::USDC),
			"USDC.e" => Ok(AssetId::USDC_E),
			"EURC.e" => Ok(AssetId::EURC_E),
			"ETH" => Ok(AssetId::ETH),
			"WETH" => Ok(AssetId::WETH),
			"WBTC.e" => Ok(AssetId::WBTC_E),
			_ => Err(()),
		}
	}
}

pub const FOREIGN_ASSETS: &str = "ForeignAssets";
pub const NATIVE_ASSETS: &str = "Assets";

const ETHEREUM_MAINNET_CHAIN_ID: u64 = 1;
const ETHEREUM_SEPOLIA_CHAIN_ID: u64 = 11155111;

const USDC_ASSET_HUB_ID: ParentchainAssetIdNative = 1337;
const USDT_ASSET_HUB_ID: ParentchainAssetIdNative = 1984;

impl AssetId {
	/// assets pallet instance name on L1. not all future assets may have such
	pub fn reserve_instance(&self) -> Option<&str> {
		match self {
			AssetId::USDT => Some(NATIVE_ASSETS),
			AssetId::USDT_E => Some(FOREIGN_ASSETS),
			AssetId::USDC => Some(NATIVE_ASSETS),
			AssetId::USDC_E => Some(FOREIGN_ASSETS),
			AssetId::EURC_E => Some(FOREIGN_ASSETS),
			AssetId::ETH => Some(FOREIGN_ASSETS),
			AssetId::WETH => Some(FOREIGN_ASSETS),
			AssetId::BTC => None,
			AssetId::WBTC_E => Some(FOREIGN_ASSETS),
		}
	}

	pub fn one_unit(&self) -> Balance {
		match self {
			AssetId::USDT => 1_000_000,
			AssetId::USDT_E => 1_000_000, // 6 decimals
			AssetId::USDC => 1_000_000,
			AssetId::USDC_E => 1_000_000,               // 6 decimals
			AssetId::EURC_E => 1_000_000,               // 6 decimals
			AssetId::ETH => 1_000_000_000_000_000_000,  // 18 decimals
			AssetId::WETH => 1_000_000_000_000_000_000, // 18 decimals
			AssetId::BTC => 100_000_000,                // 8 decimals
			AssetId::WBTC_E => 100_000_000,             // 8 decimals
		}
	}

	pub fn is_shieldable(&self, genesis_hash: Hash) -> bool {
		Self::all_shieldable(genesis_hash).contains(self)
	}

	/// returns all AssetId variants which are shieldable for a given shielding target genesis hash.
	/// L2 fee payment will be attempted in order provided here.
	pub fn all_shieldable(genesis_hash: Hash) -> Vec<Self> {
		match genesis_hash.into() {
			ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX => vec![
				AssetId::USDT,
				AssetId::USDT_E,
				AssetId::USDC,
				AssetId::USDC_E,
				AssetId::EURC_E,
				AssetId::WETH,
				AssetId::ETH,
				AssetId::WBTC_E,
			],
			ASSET_HUB_PASEO_GENESIS_HASH_HEX => vec![AssetId::USDT, AssetId::USDC, AssetId::WETH],
			ASSET_HUB_POLKADOT_GENESIS_HASH_HEX => vec![
				AssetId::USDT_E,
				AssetId::USDC_E,
				AssetId::EURC_E,
				AssetId::ETH,
				AssetId::WBTC_E,
			],
			_ => vec![],
		}
	}
}

impl AssetTranslation for AssetId {
	/// into XCM location. Only applies to foreign assets
	fn into_location(self, genesis_hash: Hash) -> Option<Location> {
		match self {
			AssetId::USDC_E =>
				if matches!(
					genesis_hash.into(),
					ASSET_HUB_POLKADOT_GENESIS_HASH_HEX | ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX
				) {
					Some(Location {
						parents: 2,
						interior: X2(Arc::new([
							GlobalConsensus(Ethereum { chain_id: ETHEREUM_MAINNET_CHAIN_ID }),
							AccountKey20 { key: USDC_E_MAINNET_CONTRACT_ADDRESS, network: None },
						])),
					})
				} else {
					None
				},
			AssetId::EURC_E =>
				if matches!(
					genesis_hash.into(),
					ASSET_HUB_POLKADOT_GENESIS_HASH_HEX | ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX
				) {
					Some(Location {
						parents: 2,
						interior: X2(Arc::new([
							GlobalConsensus(Ethereum { chain_id: ETHEREUM_MAINNET_CHAIN_ID }),
							AccountKey20 { key: EURC_E_MAINNET_CONTRACT_ADDRESS, network: None },
						])),
					})
				} else {
					None
				},
			AssetId::USDT_E =>
				if matches!(
					genesis_hash.into(),
					ASSET_HUB_POLKADOT_GENESIS_HASH_HEX | ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX
				) {
					Some(Location {
						parents: 2,
						interior: X2(Arc::new([
							GlobalConsensus(Ethereum { chain_id: ETHEREUM_MAINNET_CHAIN_ID }),
							AccountKey20 { key: USDT_E_MAINNET_CONTRACT_ADDRESS, network: None },
						])),
					})
				} else {
					None
				},
			AssetId::WBTC_E =>
				if matches!(
					genesis_hash.into(),
					ASSET_HUB_POLKADOT_GENESIS_HASH_HEX | ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX
				) {
					Some(Location {
						parents: 2,
						interior: X2(Arc::new([
							GlobalConsensus(Ethereum { chain_id: ETHEREUM_MAINNET_CHAIN_ID }),
							AccountKey20 { key: WBTC_E_MAINNET_CONTRACT_ADDRESS, network: None },
						])),
					})
				} else {
					None
				},
			AssetId::WETH =>
				if matches!(
					genesis_hash.into(),
					ASSET_HUB_PASEO_GENESIS_HASH_HEX | ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX
				) {
					Some(Location {
						parents: 2,
						interior: X2(Arc::new([
							GlobalConsensus(Ethereum { chain_id: ETHEREUM_SEPOLIA_CHAIN_ID }),
							AccountKey20 { key: WETH_SEPOLIA_CONTRACT_ADDRESS, network: None },
						])),
					})
				} else {
					None
				},
			AssetId::ETH =>
				if matches!(
					genesis_hash.into(),
					ASSET_HUB_POLKADOT_GENESIS_HASH_HEX | ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX
				) {
					Some(Location {
						parents: 2,
						interior: X1(Arc::new([GlobalConsensus(Ethereum {
							chain_id: ETHEREUM_MAINNET_CHAIN_ID,
						})])),
					})
				} else {
					None
				},
			_ => None,
		}
	}

	/// converts our asset into an Asset Hub asset index only if shielding asset is supported on shielding target
	fn into_asset_hub_index(self, genesis_hash: Hash) -> Option<ParentchainAssetIdNative> {
		match self {
			AssetId::USDT =>
				if matches!(
					genesis_hash.into(),
					ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX | ASSET_HUB_PASEO_GENESIS_HASH_HEX
				) {
					Some(USDT_ASSET_HUB_ID)
				} else {
					None
				},
			AssetId::USDC =>
				if matches!(
					genesis_hash.into(),
					ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX | ASSET_HUB_PASEO_GENESIS_HASH_HEX
				) {
					Some(USDC_ASSET_HUB_ID)
				} else {
					None
				},
			_ => None,
		}
	}

	/// converts the XCM location of foreign assets to our local type only if supported for shielding target
	fn from_location(location: &Location, genesis_hash: Hash) -> Option<Self>
	where
		Self: Sized,
	{
		if location.parents == 2 {
			match &location.interior {
				X1(junctions) => match junctions.as_slice() {
					[GlobalConsensus(Ethereum { chain_id: ETHEREUM_MAINNET_CHAIN_ID })]
						if matches!(
							genesis_hash.into(),
							ASSET_HUB_POLKADOT_GENESIS_HASH_HEX
								| ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX
						) =>
						Some(AssetId::ETH),
					_ => None,
				},
				X2(junctions) => match junctions.as_slice() {
					[GlobalConsensus(Ethereum { chain_id: ETHEREUM_MAINNET_CHAIN_ID }), AccountKey20 { key: contract, network: None }]
						if *contract == USDC_E_MAINNET_CONTRACT_ADDRESS
							&& matches!(
								genesis_hash.into(),
								ASSET_HUB_POLKADOT_GENESIS_HASH_HEX
									| ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX
							) =>
						Some(AssetId::USDC_E),
					[GlobalConsensus(Ethereum { chain_id: ETHEREUM_MAINNET_CHAIN_ID }), AccountKey20 { key: contract, network: None }]
						if *contract == EURC_E_MAINNET_CONTRACT_ADDRESS
							&& matches!(
								genesis_hash.into(),
								ASSET_HUB_POLKADOT_GENESIS_HASH_HEX
									| ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX
							) =>
						Some(AssetId::EURC_E),
					[GlobalConsensus(Ethereum { chain_id: ETHEREUM_MAINNET_CHAIN_ID }), AccountKey20 { key: contract, network: None }]
						if *contract == USDT_E_MAINNET_CONTRACT_ADDRESS
							&& matches!(
								genesis_hash.into(),
								ASSET_HUB_POLKADOT_GENESIS_HASH_HEX
									| ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX
							) =>
						Some(AssetId::USDT_E),
					[GlobalConsensus(Ethereum { chain_id: ETHEREUM_MAINNET_CHAIN_ID }), AccountKey20 { key: contract, network: None }]
						if *contract == WBTC_E_MAINNET_CONTRACT_ADDRESS
							&& matches!(
								genesis_hash.into(),
								ASSET_HUB_POLKADOT_GENESIS_HASH_HEX
									| ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX
							) =>
						Some(AssetId::WBTC_E),
					[GlobalConsensus(Ethereum { chain_id: ETHEREUM_SEPOLIA_CHAIN_ID }), AccountKey20 { key: contract, network: None }]
						if *contract == WETH_SEPOLIA_CONTRACT_ADDRESS
							&& matches!(
								genesis_hash.into(),
								ASSET_HUB_PASEO_GENESIS_HASH_HEX
									| ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX
							) =>
						Some(AssetId::WETH),
					_ => None,
				},
				_ => None,
			}
		} else {
			None
		}
	}

	/// converts the index of a native Asset Hub asset to our local type only if supported for shielding target
	fn from_asset_hub_index(id: ParentchainAssetIdNative, genesis_hash: Hash) -> Option<Self> {
		if matches!(
			genesis_hash.into(),
			ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX | ASSET_HUB_PASEO_GENESIS_HASH_HEX
		) {
			match id {
				USDC_ASSET_HUB_ID => Some(AssetId::USDC),
				USDT_ASSET_HUB_ID => Some(AssetId::USDT),
				_ => None,
			}
		} else {
			None
		}
	}
}

pub trait AssetTranslation {
	fn into_location(self, genesis_hash: Hash) -> Option<Location>;

	fn into_asset_hub_index(self, genesis_hash: Hash) -> Option<ParentchainAssetIdNative>;
	fn from_location(loc: &Location, genesis_hash: Hash) -> Option<Self>
	where
		Self: Sized;

	fn from_asset_hub_index(id: ParentchainAssetIdNative, genesis_hash: Hash) -> Option<Self>
	where
		Self: Sized;
}
