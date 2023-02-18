use crate::{
    test::mocks::verifier_mock::VerifierMock,
    BlockImport,
    Error,
    Result,
    BlockImportQueueWorker, 
    SyncBlockFromPeer,
};
use its_test::{
	sidechain_block_builder::SidechainBlockBuilderTrait,
	sidechain_block_builder::SidechainBlockBuilder,
	sidechain_block_data_builder::SidechainBlockDataBuilder as SidechainBlockData,
	sidechain_header_builder::SidechainHeaderBuilder as SidechainHeader,
};
use core::marker::PhantomData;
use itp_sgx_crypto::aes::Aes;
use itp_sgx_externalities::SgxExternalities;
use itp_test::mock::onchain_mock::OnchainMock;
use itp_types::{H256};
use its_primitives::traits::{ShardIdentifierFor, SignedBlock as SignedSidechainBlockTrait};
use sp_core::Pair;
use itp_block_import_queue::PopFromBlockQueue;
use its_primitives::{
	traits::{Block as BlockT, Header as HeaderT},
	types::{block_data::BlockData, header::SidechainHeader as Header, Block, SignedBlock}
};
use sp_runtime::traits::Block as ParentchainBlockTrait;
use std::{collections::VecDeque, sync::RwLock};

#[derive(Default)]
pub struct BlockQueueBuilder<B, Builder> {
	queue: VecDeque<B>,
	_phantom_data: PhantomData<Builder>,
}

impl<B, Builder> BlockQueueBuilder<B, Builder>
where
	Builder: SidechainBlockBuilderTrait<Block = Block> + Default,
	B: BlockT + From<Block>
{

	fn new() -> Self {
		Self {
			queue: VecDeque::new(),
			_phantom_data: PhantomData::default(),
		}
	}

	fn build_queue(&mut self, f: impl Fn(VecDeque<B>) -> VecDeque<B>) -> VecDeque<B> {
		self.add_genesis_block_to_queue();
		f(self.queue.clone())
	}

	fn add_genesis_block_to_queue(&mut self) {
		let genesis_header = Header {
						block_number: 0,
						parent_hash: H256::from_slice(&[0; 32]),
						..Default::default()
					};
		let block: B = Builder::default().with_header(genesis_header).build().into();
		self.queue.push_back(block);
	}
}

mod tests {
	use super::*;

	#[test]
	fn process_sequential_queue_no_forks() {

		let queue = <BlockQueueBuilder<Block, SidechainBlockBuilder>>::new().build_queue(|mut queue| {
			for i in 1..5 {
				let parent_header = queue.back().unwrap().header();
				let header = Header {
					block_number: i,
					parent_hash: parent_header.hash(),
					..Default::default()
				};
				queue.push_back(SidechainBlockBuilder::default().with_header(header).build());
			}
			queue
		});

		// printing queue to view
		queue.iter().for_each(|block| println!("queue item is {:?}", block));
		// TODO: Add blocks to the fork-tree and assert that everything is correct
		//
		// H1 - H2 - H3 - H4 - H5
		//
		println!("Process Sequential Queue With No Forks");
	}

	#[test]
	fn process_sequential_queue_with_forks() {
		// TODO: Make sure this works correctly
		//
		//   - H2..
		//  /
		// H1..   - H4..
		//  \   /
		//   - H3..
		//      \
		//       - H5..
		//
		todo!();
		println!("Process Sequential Queue with Forks")
	}
}