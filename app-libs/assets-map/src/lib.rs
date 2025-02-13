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

use alloc::sync::Arc;
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
		Junctions::X2,
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
	/// USDT Tether, minted natively
	USDT = 10,
	/// USDC Circle, minted natively
	USDC = 20,
	/// USDC Circle, minted on Ethereum
	USDC_E = 21u32,
	/// Ethereum ETH,
	ETH = 30,
	/// wrapped ETH
	WETH = 31,
}

const USDC_E_MAINNET_CONTRACT_ADDRESS: [u8; 20] = hex!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
const WETH_SEPOLIA_CONTRACT_ADDRESS: [u8; 20] = hex!("fff9976782d46cc05630d1f6ebab18b2324d6b14");

/// The AssetId type we use on L2 to map all possible locations/instances
/// This type must contain unique definitions for any token we may want to shield on any shielding target
/// The decision, which types are to be supported by which shielding target happens in `is_shieldable`.
#[cfg(feature = "std")]
impl std::fmt::Display for AssetId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			AssetId::USDT => write!(f, "USDT"),
			AssetId::USDC => write!(f, "USDC"),
			AssetId::USDC_E => write!(f, "USDC.e"),
			AssetId::ETH => write!(f, "ETH"),
			AssetId::WETH => write!(f, "WETH"),
		}
	}
}

#[cfg(feature = "std")]
impl TryFrom<&str> for AssetId {
	type Error = ();

	fn try_from(symbol: &str) -> Result<Self, Self::Error> {
		match symbol {
			"USDT" => Ok(AssetId::USDT),
			"USDC" => Ok(AssetId::USDC),
			"USDC.e" => Ok(AssetId::USDC_E),
			"ETH" => Ok(AssetId::ETH),
			"WETH" => Ok(AssetId::WETH),
			_ => Err(()),
		}
	}
}

const FOREIGN_ASSETS: &str = "ForeignAssets";
const NATIVE_ASSETS: &str = "Assets";

const ETHEREUM_MAINNET_CHAIN_ID: u64 = 1;
const ETHEREUM_SEPOLIA_CHAIN_ID: u64 = 11155111;

const USDC_ASSET_HUB_ID: ParentchainAssetIdNative = 1337;
const USDT_ASSET_HUB_ID: ParentchainAssetIdNative = 1984;

impl AssetId {
	/// assets pallet instance name on L1. not all future assets may have such
	pub fn reserve_instance(&self) -> Option<&str> {
		match self {
			AssetId::USDT => Some(NATIVE_ASSETS),
			AssetId::USDC => Some(NATIVE_ASSETS),
			AssetId::USDC_E => Some(FOREIGN_ASSETS),
			AssetId::ETH => Some(FOREIGN_ASSETS),
			AssetId::WETH => Some(FOREIGN_ASSETS),
		}
	}

	pub fn one_unit(&self) -> Balance {
		match self {
			AssetId::USDT => 1_000_000,
			AssetId::USDC => 1_000_000,
			AssetId::USDC_E => 1_000_000,               // 6 decimals
			AssetId::ETH => 1_000_000_000_000_000_000,  // 18 decimals
			AssetId::WETH => 1_000_000_000_000_000_000, // 18 decimals
		}
	}

	pub fn is_shieldable(&self, genesis_hash: Hash) -> bool {
		let genesis_hash_hex = hex::encode(genesis_hash);
		match genesis_hash_hex.as_ref() {
			ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX => match self {
				AssetId::USDT => true,
				AssetId::USDC => true,
				AssetId::USDC_E => true,
				AssetId::ETH => true,
				AssetId::WETH => true,
			},
			ASSET_HUB_PASEO_GENESIS_HASH_HEX => match self {
				AssetId::USDT => true,
				AssetId::USDC => true,
				AssetId::USDC_E => true,
				AssetId::ETH => true,
				AssetId::WETH => true,
			},
			ASSET_HUB_POLKADOT_GENESIS_HASH_HEX => match self {
				AssetId::USDC_E => true,
				_ => false,
			},
			_ => false,
		}
	}
}

impl AssetTranslation for AssetId {
	/// into XCM location. Only applies to foreign assets
	fn into_location(self, genesis_hash: Hash) -> Option<Location> {
		let genesis_hash_hex = hex::encode(genesis_hash);
		match self {
			AssetId::USDC_E =>
				if matches!(
					genesis_hash_hex.as_ref(),
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
			AssetId::WETH =>
				if matches!(genesis_hash_hex.as_ref(), ASSET_HUB_PASEO_GENESIS_HASH_HEX) {
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
			_ => None,
		}
	}

	/// converts our asset into an Asset Hub asset index only if shielding asset is supported on shielding target
	fn into_asset_hub_index(self, genesis_hash: Hash) -> Option<ParentchainAssetIdNative> {
		let genesis_hash_hex = hex::encode(genesis_hash);
		match self {
			AssetId::USDT =>
				if matches!(
					genesis_hash_hex.as_ref(),
					ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX | ASSET_HUB_PASEO_GENESIS_HASH_HEX
				) {
					Some(USDT_ASSET_HUB_ID)
				} else {
					None
				},
			AssetId::USDC =>
				if matches!(
					genesis_hash_hex.as_ref(),
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
		let genesis_hash_hex = hex::encode(genesis_hash);
		if location.parents == 2 {
			if let X2(junctions) = &location.interior {
				match junctions.as_slice() {
					[GlobalConsensus(Ethereum { chain_id: ETHEREUM_MAINNET_CHAIN_ID }), AccountKey20 { key: contract, network: None }]
						if *contract == USDC_E_MAINNET_CONTRACT_ADDRESS
							&& matches!(
								genesis_hash_hex.as_ref(),
								ASSET_HUB_POLKADOT_GENESIS_HASH_HEX
									| ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX
							) =>
						Some(AssetId::USDC_E),
					[GlobalConsensus(Ethereum { chain_id: ETHEREUM_SEPOLIA_CHAIN_ID }), AccountKey20 { key: contract, network: None }]
						if *contract == WETH_SEPOLIA_CONTRACT_ADDRESS
							&& matches!(
								genesis_hash_hex.as_ref(),
								ASSET_HUB_PASEO_GENESIS_HASH_HEX
									| ASSET_HUB_LOCAL_TEST_GENESIS_HASH_HEX
							) =>
						Some(AssetId::USDC_E),
					_ => None,
				}
			} else {
				None
			}
		} else {
			None
		}
	}

	/// converts the index of a native Asset Hub asset to our local type only if supported for shielding target
	fn from_asset_hub_index(id: ParentchainAssetIdNative, genesis_hash: Hash) -> Option<Self> {
		let genesis_hash_hex = hex::encode(genesis_hash);
		if matches!(
			genesis_hash_hex.as_ref(),
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
