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
			block_data_hash: H256::random(),
			..Default::default()
		}
	}
}

// TODO: Mock BlockImportQueueWorker `process_queue` now that Queues can be built to be processed

mod tests {
	use super::*;

	#[test]
	fn process_sequential_queue_no_forks() {
		// Construct a queue which is sequential with 5 members all with distinct block numbers and parents
		let mut queue = <BlockQueueBuilder<Block, SidechainBlockBuilder>>::new().build_queue(|mut queue| {
			for i in 1..5 {
				let parent_header = queue.back().unwrap().header();
				let header = <BlockQueueHeaderBuilder<u64, H256>>::build_queue_header(i, parent_header.hash());
				queue.push_back(SidechainBlockBuilder::default().with_header(header).build());
			}
			queue
		});

		// queue -> [0, 1, 2, 3, 4]
		assert_eq!(queue.len(), 5);
		
		// Store all block_headers in db
		let mut db = <HeaderDb<H256, Header>>::from(
			queue.iter().map(|block| (block.hash(), *block.header())).collect::<Vec<_>>().as_slice()
		);

		// Import into forktree
		let is_descendent_of = 
			<IsDescendentOfBuilder<H256, HeaderDb<H256, Header>, TestError>>::build_is_descendent_of(None, &db);
		let mut tree = <ForkTree<H256, u64, ()>>::new();
		queue.iter().for_each(|block| {
			let _ = tree.import(block.header.hash(), block.header.block_number(), (), &is_descendent_of).unwrap();
		});

		// We have a tree which looks like this H0 is the only root
		//
		// H0 - H1 - H2 - H3 - H4
		//

		// We see that the only root of this tree is so far H0
		assert_eq!(
			tree.roots().map(|(h, n, _)| (*h, *n)).collect::<Vec<_>>(),
			vec![(queue.front().unwrap().header.hash(), 0)]
		);

		// Now finalize H0 and so the new Root should be H1
		tree.finalize_root(&queue.front().unwrap().header.hash()).unwrap();
		let _ = queue.pop_front();
		assert_eq!(
			tree.roots().map(|(h, n, _)| (*h, *n)).collect::<Vec<_>>(),
			vec![(queue.front().unwrap().header.hash(), 1)]
		);
	}

	#[test]
	fn process_sequential_queue_with_forks() {
		// Construct a queue which is sequential and every odd member has 3 block numbers which are the same
		let mut queue = <BlockQueueBuilder<Block, SidechainBlockBuilder>>::new().build_queue(|mut queue| {
			for i in 1..8 {
				let parent_header = queue.back().unwrap().header();
				if i % 2 == 0 && i != 1 { // 1 is not even want all odds to have 2 of the same block_number
					let header = <BlockQueueHeaderBuilder<u64, H256>>::build_queue_header(i, parent_header.hash());
					queue.push_back(SidechainBlockBuilder::default().with_header(header).build());
				} else {
					// build a Queue with 2 headers which are of the same block_number
					let mut headers = vec![
						<BlockQueueHeaderBuilder<u64, H256>>::build_queue_header(i, parent_header.hash()),
						<BlockQueueHeaderBuilder<u64, H256>>::build_queue_header(i, parent_header.hash())
					];
					headers.iter().for_each(|header| {
						queue.push_back(SidechainBlockBuilder::default().with_header(*header).build());
					});
				}
			}
			queue
		});

		// queue -> [0, 1, 1, 2, 3, 3, 4, 5, 5, 6, 7, 7]
		assert_eq!(queue.len(), 12);

		// Store all block_headers in db
		let mut db = <HeaderDb<H256, Header>>::from(
			queue.iter().map(|block| (block.hash(), *block.header())).collect::<Vec<_>>().as_slice()
		);

		// Import into forktree
		let is_descendent_of = 
			<IsDescendentOfBuilder<H256, HeaderDb<H256, Header>, TestError>>::build_is_descendent_of(None, &db);
		let mut tree = <ForkTree<H256, u64, ()>>::new();
		queue.iter().for_each(|block| {
			let _ = tree.import(block.header.hash(), block.header.block_number(), (), &is_descendent_of).unwrap();
		});

		// We have a tree which looks like the following
		//                      - (H5, B3)..
		//                     /
		//		 	 - (H3, B2)
		//			/          \
		//   	 - (H1, B1)     - (H4, B3)..
		//  	/
		//	   /	 
		// (H0, B0)   
		//     \
		//  	\	
		//		 - (H2, B1)..
		//
		//

		// H0 is the first root
		assert_eq!(
			tree.roots().map(|(h, n, _)| (*h, *n)).collect::<Vec<_>>(),
			vec![(queue.front().unwrap().header.hash(), 0)]
		);

		// Now if we finalize H0 we should see 2 roots H1 and H2
		tree.finalize_root(&queue.front().unwrap().header.hash()).unwrap();
		let _ = queue.pop_front();
		assert_eq!(
			tree.roots().map(|(h, n, _)| (*h, *n)).collect::<Vec<_>>(),
			vec![(queue[1].header.hash(), 1), (queue[0].header.hash(), 1)]
		);

		// If we finalize (H1, B1) then we should see one roots (H3, B2)
		let _ = queue.pop_front(); // remove (H1, B1)
		tree.finalize_root(&queue.front().unwrap().header.hash()).unwrap();
		let _ = queue.pop_front(); // remove (H2, B1)
		assert_eq!(
			tree.roots().map(|(h, n, _)| (*h, *n)).collect::<Vec<_>>(),
			vec![(queue[0].header.hash(), 2)]
		);

		// If we finalize (H3, B2) we should see two roots (H4, B3), (H5, B3)
		tree.finalize_root(&queue.front().unwrap().header.hash()).unwrap();
		let _ = queue.pop_front(); // remove (H3, B2)
		assert_eq!(
			tree.roots().map(|(h, n, _)| (*h, *n)).collect::<Vec<_>>(),
			vec![(queue[1].header.hash(), 3), (queue[0].header.hash(), 3)]
		);
	}
}

#[test]
fn process_non_sequential_queue_without_forks() {
	todo!()
}

#[test]
fn process_non_sequential_queue_with_forks() {
	todo!()
}
