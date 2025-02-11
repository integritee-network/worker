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

#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
extern crate alloc;
extern crate core;

use alloc::sync::Arc;
use codec::{Decode, Encode, MaxEncodedLen};
use hex_literal::hex;
use itp_types::xcm::{
	Junction::{AccountKey20, GlobalConsensus},
	Junctions::X2,
	Location,
	NetworkId::Ethereum,
};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};

#[derive(
	Decode,
	Encode,
	Clone,
	Default,
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
	#[default]
	UNSUPPORTED = 0,
	USDC_E = 1,
}

const USDC_E_CONTRACT_ADDRESS: [u8; 20] = hex!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");

#[cfg(feature = "std")]
impl std::fmt::Display for AssetId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			AssetId::USDC_E => write!(f, "USDC.e"),
			AssetId::UNSUPPORTED => write!(f, "UNSUPPORTED"),
		}
	}
}

#[cfg(feature = "std")]
impl TryFrom<&str> for AssetId {
	type Error = ();

	fn try_from(symbol: &str) -> Result<Self, Self::Error> {
		match symbol {
			"USDC.e" => Ok(AssetId::USDC_E),
			_ => Err(()),
		}
	}
}

const FOREIGN_ASSETS: &str = "ForeignAssets";

impl AssetId {
	pub fn reserve_instance(&self) -> Option<&str> {
		match self {
			AssetId::USDC_E => Some(FOREIGN_ASSETS),
			AssetId::UNSUPPORTED => None,
		}
	}
}

impl AssetTranslation for AssetId {
	fn into_location(self) -> Option<Location> {
		match self {
			AssetId::USDC_E => Some(Location {
				parents: 2,
				interior: X2(Arc::new([
					GlobalConsensus(Ethereum { chain_id: 1 }),
					AccountKey20 { key: USDC_E_CONTRACT_ADDRESS, network: None },
				])),
			}),
			AssetId::UNSUPPORTED => None,
		}
	}

	fn from_location(location: &Location) -> Option<Self>
	where
		Self: Sized,
	{
		if location.parents == 2 {
			if let X2(junctions) = &location.interior {
				match junctions.as_slice() {
					[GlobalConsensus(Ethereum { chain_id: 1 }), AccountKey20 { key: contract, network: None }]
						if *contract == USDC_E_CONTRACT_ADDRESS =>
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
}

pub trait AssetTranslation {
	fn into_location(self) -> Option<Location>;
	fn from_location(loc: &Location) -> Option<Self>
	where
		Self: Sized;
}
