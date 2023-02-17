use crate::{
    test::mocks::verifier_mock::VerifierMock,
    BlockImport,
    Error,
    Result,
    BlockImportQueueWorker, 
    SyncBlockFromPeer,
};
use its_test::{
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

pub struct BlockImportQueueWorkerMock {
	block_import_queue: VecDeque<Block>,
}

impl BlockImportQueueWorkerMock {
	pub fn new(
	) -> Self {
		BlockImportQueueWorkerMock {
			block_import_queue: <VecDeque<Block>>::default(),
		}
	}

	pub fn construct_mock_queue_sequential_no_forks(mut self, size: u64) -> Self {
		// Construct a queue which is a happy bath for incoming blocks 1-> 2-> 3-> .. etc no duplicates
		self.add_genesis_block_to_queue();
		for i in 1..size {
			self.add_block_to_sequential_queue(i);
		}
		self
	}

	// Add a genesis block to the queue
	fn add_genesis_block_to_queue(&mut self) {
		let genesis_header = Header {
			block_number: 0,
			parent_hash: H256::from_slice(&[0; 32]),
			..Default::default()
		};
		self.block_import_queue.push_back(SidechainBlockBuilder::default().with_header(genesis_header).build());
	}

	fn add_block_to_sequential_queue(&mut self, block_number: u64) {
		let parent_header = self.block_import_queue.back().unwrap().header();
		let header = Header {
			block_number,
			parent_hash: parent_header.hash(),
			..Default::default()
		};
		self.block_import_queue.push_back(SidechainBlockBuilder::default().with_header(header).build());
	}

	pub fn print_queue(&self) {
		self.block_import_queue.iter().for_each(|block| println!("queue item is {:?}", block));
	}
}

impl Default for BlockImportQueueWorkerMock {
	fn default() -> Self {
		BlockImportQueueWorkerMock {
			block_import_queue: <VecDeque<Block>>::default(),
		}
	}
}

mod tests {
	use super::*;

	#[test]
	fn process_sequential_queue_no_forks() {
		let import_worker = BlockImportQueueWorkerMock::default();
		import_worker.construct_mock_queue_sequential_no_forks(5).print_queue();
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
