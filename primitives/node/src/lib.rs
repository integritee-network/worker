#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

use codec::{Decode, Encode};
#[cfg(feature = "sgx")]
use sgx_tstd as std;
use sp_core::H256;
use std::vec::Vec;

/// Substrate runtimes provide no string type. Hence, for arbitrary data of varying length the
/// `Vec<u8>` is used. In the polkadot-js the typedef `Text` is used to automatically
/// utf8 decode bytes into a string.
#[cfg(not(feature = "std"))]
pub type PalletString = Vec<u8>;

#[cfg(feature = "std")]
pub type PalletString = String;

#[cfg(feature = "std")]
pub type SignedBlock = sp_runtime::generic::SignedBlock<my_node_runtime::Block>;

pub use sp_core::crypto::AccountId32 as AccountId;

pub type ShardIdentifier = H256;
pub type BlockNumber = u32;

// Note in the substratee-pallet-registry this is a struct. But for the codec this does not matter.
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug)]
pub struct Request {
    pub shard: ShardIdentifier,
    pub cyphertext: Vec<u8>,
}

pub type IpfsHash = [u8; 46];

pub type SubstrateeConfirmCallFn = ([u8; 2], ShardIdentifier, H256, Vec<u8>);
pub type ShieldFundsFn = ([u8; 2], Vec<u8>, u128, ShardIdentifier);
pub type CallWorkerFn = ([u8; 2], Request);

// Todo: move this improved enclave definition into a primitives crate in the substratee-registry repo.
#[derive(Encode, Decode, Default, Clone, PartialEq, sp_core::RuntimeDebug)]
pub struct EnclaveGen<AccountId> {
    pub pubkey: AccountId,
    // FIXME: this is redundant information
    pub mr_enclave: [u8; 32],
    pub timestamp: u64,
    // unix epoch in milliseconds
    pub url: PalletString, // utf8 encoded url
}

impl<AccountId> EnclaveGen<AccountId> {
    pub fn new(pubkey: AccountId, mr_enclave: [u8; 32], timestamp: u64, url: PalletString) -> Self {
        Self {
            pubkey,
            mr_enclave,
            timestamp,
            url,
        }
    }
}

pub type Enclave = EnclaveGen<AccountId>;
