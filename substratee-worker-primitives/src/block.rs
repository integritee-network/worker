#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

use codec::{Decode, Encode};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "sgx")]
use sgx_tstd as std;
use std::vec::Vec;

use sp_core::H256;
use substratee_stf::{ShardIdentifier, AccountId, Signature};



/// Simplified block structure for relay chain submission as an extrinsic
#[derive(PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Block {
    pub block_number: u64,
    pub parent_hash: H256,
    pub timestamp: i64,
    /// Hash of the last layer one block header
    ///  needed because extrinsics can depend on layer one state 
    pub layer_one_head: H256,
    pub shard_id: ShardIdentifier,
    pub block_author: AccountId,
    pub extrinsic_hashes: Vec<H256>,
    pub state_hash_apriori: H256,
    pub state_hash_aposterior: H256,
    pub state_update: Vec<u8>,
    pub block_author_signature: Signature,
}