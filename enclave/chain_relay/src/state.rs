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
    pub unjustified_headers: Vec<Block::Header>, // Finalized headers without grandpa proof
    pub verify_tx_inclusion: Vec<OpaqueExtrinsic>, // Transactions sent by the relay
    pub scheduled_change: Option<ScheduledChangeAtBlock<Block::Header>>, // Scheduled Authorities change as indicated in the header's digest.
}

#[derive(Encode, Decode, Clone, PartialEq)]
pub struct ScheduledChangeAtBlock<Header: HeaderT> {
    pub at_block: Header::Number,
    pub next_authority_list: AuthorityList,
}

impl<Block: BlockT> RelayState<Block> {
    pub fn new(block_header: Block::Header, validator_set: AuthorityList) -> Self {
        RelayState {
            last_finalized_block_header: block_header.clone(),
            current_validator_set: validator_set,
            current_validator_set_id: 0,
            headers: vec![block_header],
            unjustified_headers: Vec::new(),
            verify_tx_inclusion: Vec::new(),
            scheduled_change: None,
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
