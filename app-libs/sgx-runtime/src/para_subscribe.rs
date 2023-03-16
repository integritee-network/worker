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

//! This is a module which listens to transfer events from a parachain sovereign account
//! and automatically calls the `balance_shield` call in order to shield funds from a parachain account
//! The module also will allow someone to unshield funds and have the unshielded funds sent
//! from the sovereign parachain account to the desired account on the parachain assosciated parachain
//! 

// #![cfg_attr(not(feature = "std"), no_std)]
// pub use pallet::*;

// #[frame_support::pallet]
// pub mod pallet {
// 	use crate::weights::WeightInfo;
// 	use frame_support::prelude::*;
// 	use frame_system::prelude::*;

// 	#[pallet::pallet]
// 	#[pallet::generate_store(pub(super) trait Store)]
// 	pub struct Pallet<T>(_);

// 	#[pallet::config]
// 	pub trait Config: frame_system::Config {
// 		type WeightInfo: WeightInfo
// 	}
// }

/// Config:
/// MAX_PARACHAINS = 3
/// PARACHAIN = Statemine // for now..

/// Extrinsics:
/// fn unshield_funds((AccountId, ParaId), amount)
/// fn register_parachain(ParaId) // Governance origin
/// fn deregister_parachain(ParaId) // Governance origin
/// 

/// Intrinsics:
    // Code that listens to the lightclient for transfers to the soverign account and calls shield
    // Shields the balance of the account along with the assosciated parachain
/// fn listen_parachain_events()

/// Storage:
    // Stores the ParaId's Associated with a particular account
/// ((AccountId, ParaId) => Balance)
/// Need new pallet balances variation that has a call `fn shield((AccountId, ParaId), amt)`
/// 


// TODO: Make small PoC which handles a very simple case of doing this
// 1.) Add some basic custom Flipper pallet and add it to runtime and call it.
// 2.) Work on listen_to_parachain_events() func
// 3.) Work on other intrinsics/extrinsics