use codec::{Decode, Encode};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "sgx")]
use sgx_tstd as std;
use std::vec::Vec;
use std::vec;

use sp_core::{sr25519, Pair, H256};
use sp_runtime::traits::Verify;
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
    state_hash_aposteriori: H256,
    /// Encrypted vec of key-value pairs to update
    state_update: Vec<u8>,
    block_author_signature: Signature,
}

impl Block {   
    /// Constructs a signed block
    pub fn construct_block(
        pair: &sr25519::Pair,
        block_number: u64,
        parent_hash: H256,
        layer_one_head: H256,
        shard: ShardIdentifier,
        author: AccountId,
        extrinsic_hashes: Vec<H256>,
        state_hash_apriori: H256,
        state_hash_aposteriori: H256,
        state_update: Vec<u8>,
    ) -> Block {
         // get timestamp for new block
         let now: i64 = Block::get_time();

        // get block payload
        let mut payload = vec![];
        payload.append(&mut block_number.encode());
        payload.append(&mut parent_hash.encode());
        payload.append(&mut now.encode());
        payload.append(&mut layer_one_head.encode());
        payload.append(&mut shard.encode());
        payload.append(&mut author.encode());
        payload.append(&mut extrinsic_hashes.encode());
        payload.append(&mut state_hash_apriori.encode());
        payload.append(&mut state_hash_aposteriori.encode());
        payload.append(&mut state_update.encode());       

        // get block signature
        let signature: Signature = pair.sign(payload.as_slice()).into();
        
        // create block
        Block {
            block_number: block_number,
            parent_hash: parent_hash,
            timestamp: now,
            layer_one_head: layer_one_head,
            shard_id: shard,
            block_author: author,
            extrinsic_hashes: extrinsic_hashes,
            state_hash_apriori: state_hash_apriori,
            state_hash_aposteriori: state_hash_aposteriori,
            state_update: state_update,
            block_author_signature: signature,
        }
    }

    /// Verifes the signature of a Block
    pub fn verify_signature(&self) -> bool {
        // get block payload
        let mut payload = vec![];
        payload.append(&mut self.block_number.encode());
        payload.append(&mut self.parent_hash.encode());
        payload.append(&mut self.timestamp.encode());
        payload.append(&mut self.layer_one_head.encode());
        payload.append(&mut self.shard_id.encode());
        payload.append(&mut self.block_author.encode());
        payload.append(&mut self.extrinsic_hashes.encode());
        payload.append(&mut self.state_hash_apriori.encode());
        payload.append(&mut self.state_hash_aposteriori.encode());
        payload.append(&mut self.state_update.encode());      
        
        // verify signature
        self.block_author_signature
            .verify(payload.as_slice(), &self.block_author)
    }


    /// sets the timestamp of the block as seconds since unix epoch
    fn get_time() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
        // = TzUtc.timestamp(now.as_secs() as i64, 0);
    }


}

/* 
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn () {
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
    } 
} */

