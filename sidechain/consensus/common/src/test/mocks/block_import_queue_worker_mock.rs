use crate::{
    test::mocks::verifier_mock::VerifierMock,
    BlockImport,
    Error,
    Result,
    BlockImportQueueWorker, 
    SyncBlockFromPeer,
	is_descendent_of_builder::{
		HeaderDb, HeaderDbTrait, IsDescendentOfBuilder, LowestCommonAncestorFinder, 
		TestError,
	},
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
use fork_tree::ForkTree;

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

pub trait BlockQueueHeaderBuild<BlockNumber, Hash> {
	type QueueHeader;
	fn build_queue_header(block_number: BlockNumber, parent_hash: Hash) -> Self::QueueHeader;
}
pub struct BlockQueueHeaderBuilder<BlockNumber, Hash>(PhantomData<(BlockNumber, Hash)>);
impl<BlockNumber, Hash> BlockQueueHeaderBuild<BlockNumber, Hash> for BlockQueueHeaderBuilder<BlockNumber, Hash>
where
	BlockNumber: Into<u64>,
	Hash: Into<H256>,
{
	type QueueHeader = Header;
	fn build_queue_header(block_number: BlockNumber, parent_hash: Hash) -> Self::QueueHeader {
		Header {
			block_number: block_number.into(),
			parent_hash: parent_hash.into(),
			..Default::default()
		}
	}
}

// TODO: Mock BlockImportQueueWorker `process_queue` now that Queues can be built to be processed

mod tests {
	use super::*;

	#[test]
	fn process_sequential_queue_no_forks() {

		let mut queue = <BlockQueueBuilder<Block, SidechainBlockBuilder>>::new().build_queue(|mut queue| {
			for i in 1..5 {
				let parent_header = queue.back().unwrap().header();
				let header = <BlockQueueHeaderBuilder<u64, H256>>::build_queue_header(i, parent_header.hash());
				queue.push_back(SidechainBlockBuilder::default().with_header(header).build());
			}
			queue
		});

		// printing queue to view
		// queue.iter().for_each(|block| println!("queue item is {:?}", block));
		
		// Store all block_headers in db
		let mut db = <HeaderDb<H256, Header>>::new();
		queue.iter().for_each(|block| {
			let _ = db.insert(block.header.hash(), block.header);
		});

		// Import into forktree
		let is_descendent_of = 
			<IsDescendentOfBuilder<H256, HeaderDb<H256, Header>, TestError>>::build_is_descendent_of(None, &db);
		let mut tree = <ForkTree<H256, u64, ()>>::new();
		queue.iter().for_each(|block| {
			let _ = tree.import(block.header.hash(), block.header.block_number(), (), &is_descendent_of).unwrap();
		});

		// We have a tree which looks like this H1 is the only root
		//
		// H1 - H2 - H3 - H4 - H5
		//

		// We see that the only root of this tree is so far H1
		assert_eq!(
			tree.roots().map(|(h, n, _)| (*h, *n)).collect::<Vec<_>>(),
			vec![(queue.front().unwrap().header.hash(), 0)]
		);

		// Now finalize H1 and so the new Root should be H2
		tree.finalize_root(&queue.front().unwrap().header.hash()).unwrap();
		let _ = queue.pop_front();
		assert_eq!(
			tree.roots().map(|(h, n, _)| (*h, *n)).collect::<Vec<_>>(),
			vec![(queue.front().unwrap().header.hash(), 1)]
		);

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
