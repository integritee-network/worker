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


/// simplified block structure for relay chain submission as an extrinsic
#[derive(PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Block {
    block_number: u64,
    parent_hash: H256,
    timestamp: i64,
    /// hash of the last header of block in layer one
    /// needed in case extrinsics depend on layer one state 
    layer_one_head: H256,    
    shard_id: ShardIdentifier,
    ///  must be registered on layer one as an enclave for the respective shard 
    block_author: AccountId,
    extrinsic_hashes: Vec<H256>,
    state_hash_apriori: H256,
    state_hash_aposteriori: H256,
    /// encrypted vec of key-value pairs to update
    state_update: Vec<u8>,
    block_author_signature: Signature,
}

impl Block {
    // get block number.
    pub fn block_number(&self) -> u64 {
        self.block_number
    }
    // get parent hash of block
    pub fn parent_hash(&self) -> H256 {
        self.parent_hash
    }
    // get timestamp of block
    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }
    // get layer one head of block
    pub fn layer_one_head(&self) -> H256 {
        self.layer_one_head
    }
    // get shard id of block
    pub fn shard_id(&self) -> ShardIdentifier {
        self.shard_id
    }
    // get author of block
    pub fn block_author(&self) -> AccountId {
        self.block_author
    }
    // get reference of extrinisics of block
    pub fn extrinsic_hashes(&self) -> &Vec<H256> {
        &self.extrinsic_hashes
    }
    // get state hash piror to block execution
    pub fn state_hash_apriori(&self) -> H256 {
        self.state_hash_apriori
    }
    // get state hash after block execution
    pub fn state_hash_aposteriori(&self) -> H256 {
        self.state_hash_aposteriori
    }
    // get reference of state diff block brings with
    pub fn state_update(&self) -> &Vec<u8> {
        &self.state_update
    }
    // get reference of block author signature
    pub fn signature(&self) -> &Signature {
        &self.block_author_signature
    }
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


#[cfg(test)]
mod tests {
    use super::*;
    use sp_keyring::AccountKeyring;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn construct_block_works() {
        let signer_pair = &AccountKeyring::Alice.pair();
        let author = signer_pair.public();
        let block_number: u64 = 0;
        let parent_hash = H256::random();
        let layer_one_head = H256::random();
        let state_hash_apriori = H256::random();
        let state_hash_aposteriori = H256::random();
        let extrinsic_hashes = vec![];
        let state_update: Vec<u8> = vec![];
        let shard = ShardIdentifier::default();

        let block = Block::construct_block(&signer_pair, block_number, parent_hash.clone(),
            layer_one_head.clone(), shard.clone(), author.clone(), extrinsic_hashes.clone(), state_hash_apriori.clone(),
            state_hash_aposteriori.clone(), state_update.clone());

        assert_eq!(block_number, block.block_number());
        assert_eq!(parent_hash, block.parent_hash());
        assert_eq!(layer_one_head, block.layer_one_head());
        assert_eq!(shard, block.shard_id());
        assert_eq!(author, block.block_author());
        assert_eq!(extrinsic_hashes, *block.extrinsic_hashes());
        assert_eq!(state_hash_apriori, block.state_hash_apriori());
        assert_eq!(state_hash_aposteriori, block.state_hash_aposteriori());
        assert_eq!(state_update, *block.state_update());
    }

    #[test]
    fn get_signature_works() {
        let signer_pair = &AccountKeyring::Alice.pair();
        let author = signer_pair.public();
        let block_number: u64 = 0;
        let parent_hash = H256::random();
        let layer_one_head = H256::random();
        let state_hash_apriori = H256::random();
        let state_hash_aposteriori = H256::random();
        let extrinsic_hashes = vec![];
        let state_update: Vec<u8> = vec![];
        let shard = ShardIdentifier::default();

        let block = Block::construct_block(&signer_pair, block_number, parent_hash.clone(),
            layer_one_head.clone(), shard.clone(), author.clone(), extrinsic_hashes.clone(), state_hash_apriori.clone(),
            state_hash_aposteriori.clone(), state_update.clone());

        assert_eq!(&block.block_author_signature, block.signature());
    }

     #[test]
    fn verify_signature_works() {
        let signer_pair = &AccountKeyring::Alice.pair();
        let author = signer_pair.public();
        let block_number: u64 = 0;
        let parent_hash = H256::random();
        let layer_one_head = H256::random();
        let state_hash_apriori = H256::random();
        let state_hash_aposteriori = H256::random();
        let extrinsic_hashes = vec![];
        let state_update: Vec<u8> = vec![];
        let shard = ShardIdentifier::default();

        let block = Block::construct_block(&signer_pair, block_number, parent_hash.clone(),
            layer_one_head.clone(), shard.clone(), author.clone(), extrinsic_hashes.clone(), state_hash_apriori.clone(),
            state_hash_aposteriori.clone(), state_update.clone());

        assert!(block.verify_signature());
    }

    #[test]
    fn tampered_block_verify_signature_fails() {
        let signer_pair = &AccountKeyring::Alice.pair();
        let author = signer_pair.public();
        let block_number: u64 = 0;
        let parent_hash = H256::random();
        let layer_one_head = H256::random();
        let state_hash_apriori = H256::random();
        let state_hash_aposteriori = H256::random();
        let extrinsic_hashes = vec![];
        let state_update: Vec<u8> = vec![];
        let shard = ShardIdentifier::default();

        let mut block = Block::construct_block(&signer_pair, block_number, parent_hash.clone(),
            layer_one_head.clone(), shard.clone(), author.clone(), extrinsic_hashes.clone(), state_hash_apriori.clone(),
            state_hash_aposteriori.clone(), state_update.clone());

        block.block_number = 1; 

        assert_eq!(block.verify_signature(), false);
    } 

    #[test]
    fn get_time_works() {        
        let two_seconds = Duration::new(2,0);
        let now = Block::get_time();        
        thread::sleep(two_seconds);
        assert_eq!(now + two_seconds.as_secs() as i64, Block::get_time());
    } 

    #[test]
    fn setting_timestamp_works() {
        let signer_pair = &AccountKeyring::Alice.pair();
        let author = signer_pair.public();
        let block_number: u64 = 0;
        let parent_hash = H256::random();
        let layer_one_head = H256::random();
        let state_hash_apriori = H256::random();
        let state_hash_aposteriori = H256::random();
        let extrinsic_hashes = vec![];
        let state_update: Vec<u8> = vec![];
        let shard = ShardIdentifier::default();

        let block = Block::construct_block(&signer_pair, block_number, parent_hash.clone(),
            layer_one_head.clone(), shard.clone(), author.clone(), extrinsic_hashes.clone(), state_hash_apriori.clone(),
            state_hash_aposteriori.clone(), state_update.clone());
        
        let one_second = Duration::new(1,0);
        let now = block.timestamp();        
        thread::sleep(one_second);
        assert_eq!(now + one_second.as_secs() as i64, Block::get_time());
    } 
} 

