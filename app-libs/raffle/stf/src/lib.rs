#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

mod trusted_call;

pub use trusted_call::{RaffleCount, RaffleIndex, RaffleTrustedCall, WinnerCount};
