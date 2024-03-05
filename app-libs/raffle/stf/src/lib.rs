#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

mod getter;
mod trusted_call;

pub use getter::{RafflePublicGetter, RaffleTrustedGetter};
pub use pallet_raffles::{
	self, merkle_tree, RaffleCount, RaffleIndex, RaffleMetadata, WinnerCount,
};
pub use trusted_call::RaffleTrustedCall;
