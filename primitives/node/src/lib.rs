#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

use codec::{Decode, Encode};
#[cfg(feature = "sgx")]
use sgx_tstd as std;
use sp_core::H256;
use std::vec::Vec;

#[cfg(feature = "std")]
mod api_ext;

#[cfg(feature = "std")]
pub use api_ext::*;

pub type ShardIdentifier = H256;
pub type BlockNumber = u32;

// Note in the substratee-pallet-registry this is a struct. But for the codec this does not matter.
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug)]
pub struct Request {
    pub shard: ShardIdentifier,
    pub cyphertext: Vec<u8>,
}

pub type SubstrateeConfirmCallFn = ([u8; 2], ShardIdentifier, H256, Vec<u8>);
pub type ShieldFundsFn = ([u8; 2], Vec<u8>, u128, ShardIdentifier);
pub type CallWorkerFn = ([u8; 2], Request);

