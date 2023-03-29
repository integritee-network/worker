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

//! Parentchain specific params. Be sure to change them if your node uses different types.

use sp_runtime::{
	generic::{self, Block as BlockG, SignedBlock as SignedBlockG, UncheckedExtrinsic},
	traits::{BlakeTwo256, IdentifyAccount, Verify},
	MultiSignature,
};

pub type StorageProof = Vec<Vec<u8>>;

// #[cfg(not(feature = "std"))]
// pub use no_std::*;
//
// #[cfg(feature = "std")]
// pub use runtime_types::*;
//
// #[cfg(not(feature = "std"))]
// pub mod no_std {
// use super::*;

// Basic Types.
pub type Index = u32;
pub type Balance = u128;
pub type Hash = sp_core::H256;

// Account Types.
pub type AccountId = sp_core::crypto::AccountId32;
pub type AccountData = pallet_balances::AccountData<Balance>;
pub type AccountInfo = frame_system::AccountInfo<Index, AccountData>;
pub type Address = sp_runtime::MultiAddress<AccountId, ()>;

// Block Types
pub type BlockNumber = u32;
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
pub type BlockHash = sp_core::H256;

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = MultiSignature;
// }

// #[cfg(feature = "std")]
// pub mod runtime_types {
// 	use super::*;
// 	use frame_system::Config as FrameSystemConfig;
// 	use my_node_runtime::Runtime;
// 	use pallet_balances::Config as BalancesConfig;
//
// 	// Basic Types.
// 	pub type Index = <Runtime as FrameSystemConfig>::Index;
// 	pub type Balance = <Runtime as BalancesConfig>::Balance;
// 	pub type Hash = <Runtime as FrameSystemConfig>::Hash;
//
// 	// Account Types.
// 	pub type AccountId = <Runtime as FrameSystemConfig>::AccountId;
// 	pub type AccountData = <Runtime as FrameSystemConfig>::AccountData;
// 	pub type AccountInfo = frame_system::AccountInfo<Index, AccountData>;
// 	pub type Address = my_node_runtime::Address;
//
// 	// Block Types
// 	pub type BlockNumber = <Runtime as FrameSystemConfig>::BlockNumber;
// 	pub type Header = <Runtime as FrameSystemConfig>::Header;
// 	pub type UncheckedExtrinsic = my_node_runtime::UncheckedExtrinsic;
// 	pub type Block = my_node_runtime::Block;
// 	pub type SignedBlock = SignedBlockG<Block>;
// 	pub type BlockHash = <Runtime as FrameSystemConfig>::Hash;
//
// 	/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
// 	pub type Signature = my_node_runtime::Signature;
// }
