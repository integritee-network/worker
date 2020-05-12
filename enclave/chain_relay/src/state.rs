use codec::{Decode, Encode};
use sp_finality_grandpa::{AuthorityList, SetId};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use sp_runtime::OpaqueExtrinsic;
use std::fmt;
use std::vec::Vec;

#[derive(Encode, Decode, Clone, PartialEq)]
pub struct RelayState<Block: BlockT> {
    pub last_finalized_block_header: Block::Header,
    pub current_validator_set: AuthorityList,
    pub current_validator_set_id: SetId,
    pub headers: Vec<Block::Header>,
    pub verify_tx_inclusion: Vec<OpaqueExtrinsic>,
}

impl<Block: BlockT> RelayState<Block> {
    pub fn new(block_header: Block::Header, validator_set: AuthorityList) -> Self {
        RelayState {
            last_finalized_block_header: block_header.clone(),
            current_validator_set: validator_set,
            current_validator_set_id: 0,
            headers: vec![block_header],
            // transactions sent by the relay
            verify_tx_inclusion: Vec::new(),
        }
    }
}

impl<Block: BlockT> fmt::Debug for RelayState<Block> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RelayInfo {{ last_finalized_block_header_number: {:?}, current_validator_set: {:?}, \
        current_validator_set_id: {} amount of transaction in tx_inclusion_queue: {} }}",
            self.last_finalized_block_header.number(),
            self.current_validator_set,
            self.current_validator_set_id,
            self.verify_tx_inclusion.len()
        )
    }
}
