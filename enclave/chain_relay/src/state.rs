use codec::{Decode, Encode};
use sp_finality_grandpa::{AuthorityList, SetId};
use sp_runtime::traits::Block as BlockT;
use std::vec::Vec;

#[derive(Encode, Decode, Clone, PartialEq)]
pub struct RelayState<Block: BlockT> {
    pub last_finalized_block_header: Block::Header,
    pub current_validator_set: AuthorityList,
    pub current_validator_set_id: SetId,
    pub headers: Vec<Block::Header>,
}

impl<Block: BlockT> RelayState<Block> {
    pub fn new(block_header: Block::Header, validator_set: AuthorityList) -> Self {
        RelayState {
            last_finalized_block_header: block_header.clone(),
            current_validator_set: validator_set,
            current_validator_set_id: 0,
            headers: vec![block_header],
        }
    }
}
