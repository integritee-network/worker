use crate::storage_proof::StorageProof;
use codec::{Decode, Encode};
use frame_system::Trait;
use sp_finality_grandpa::{AuthorityList, SetId};
use sp_runtime::traits::Block as BlockT;
use std::marker::PhantomData;
use std::vec::Vec;

#[derive(Encode, Decode, Clone, PartialEq)]
pub struct RelayInitState<Block: BlockT, T: Trait> {
    pub _phantom: PhantomData<T>,
    pub block_header: Block::Header,
    pub validator_set: AuthorityList,
    pub validator_set_proof: StorageProof,
}

#[derive(Encode, Decode, Clone, PartialEq)]
pub struct RelayState<Block: BlockT, T: Trait> {
    pub _marker: PhantomData<T>,
    pub last_finalized_block_header: Block::Header,
    pub current_validator_set: AuthorityList,
    pub current_validator_set_id: SetId,
    pub headers: Vec<Block::Header>,
}

impl<Block: BlockT, T: Trait> RelayState<Block, T> {
    pub fn new(block_header: Block::Header, validator_set: AuthorityList) -> Self {
        RelayState {
            _marker: PhantomData,
            last_finalized_block_header: block_header.clone(),
            current_validator_set: validator_set,
            current_validator_set_id: 0,
            headers: vec![block_header],
        }
    }
}
