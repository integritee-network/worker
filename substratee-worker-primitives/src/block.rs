use codec::{Decode, Encode};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "sgx")]
use sgx_tstd as std;
use std::vec::Vec;

use sp_core::H256;
use substratee_stf::{ShardIdentifier, AccountId, Signature};

use std::time::{UNIX_EPOCH, SystemTime};
#[cfg(feature = "sgx")]
use std::untrusted::time::SystemTimeEx;
/* use chrono::Utc as TzUtc;
use chrono::TimeZone; */


/// Simplified block structure for relay chain submission as an extrinsic
#[derive(PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Block {
    block_number: u64,
    parent_hash: H256,
    timestamp: i64,
    /// Hash of the last header of block in layer one
    /// Needed in case extrinsics depend on layer one state 
    layer_one_head: H256,    
    shard_id: ShardIdentifier,
    ///  Must be registered on layer one as an enclave for the respective shard 
    block_author: AccountId,
    extrinsic_hashes: Vec<H256>,
    state_hash_apriori: H256,
    state_hash_aposterior: H256,
    /// Encrypted vec of key-value pairs to update
    state_update: Vec<u8>,
    block_author_signature: Signature,
}

impl Block {
    /// Sign the block with the authors signature
    pub fn sign() {
        // 
    }

    /// sets the timestamp of current time
    fn set_timestamp(&mut self) {
        self.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // = TzUtc.timestamp(now.as_secs() as i64, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /* use sp_keyring::AccountKeyring;

    #[test]
    fn verify_signature_works() {
        let nonce = 21;
        let mrenclave = [0u8; 32];
        let shard = ShardIdentifier::default();

        let call = TrustedCall::balance_set_balance(
            AccountKeyring::Alice.public(),
            AccountKeyring::Alice.public(),
            42,
            42,
        );
        let signed_call = call.sign(&AccountKeyring::Alice.pair(), nonce, &mrenclave, &shard);

        assert!(signed_call.verify_signature(&mrenclave, &shard));
    } */
}

