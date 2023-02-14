use crate::{
    test::mocks::verifier_mock::VerifierMock,
    BlockImport,
    Error,
    Result,
    BlockImportQueueWorker, 
    SyncBlockFromPeer,
};
use core::marker::PhantomData;
use itp_sgx_crypto::aes::Aes;
use itp_sgx_externalities::SgxExternalities;
use itp_test::mock::onchain_mock::OnchainMock;
use itp_types::H256;
use its_primitives::traits::{ShardIdentifierFor, SignedBlock as SignedSidechainBlockTrait};
use sp_core::Pair;
use itp_block_import_queue::PopFromBlockQueue;
use its_primitives::traits::{Block as BlockTrait, Header};
use sp_runtime::traits::Block as ParentchainBlockTrait;
use std::{collections::VecDeque, sync::RwLock};

pub struct BlockImportQueueWorkerMock<ParentchainBlock, SignedSidechainBlock, BlockImportQueue, PeerBlockSyncer>
where
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	SignedSidechainBlock:
		SignedSidechainBlockTrait<Public = <sp_core::ed25519::Pair as Pair>::Public> + 'static,
{
	_phantom: PhantomData<(ParentchainBlock, SignedSidechainBlock, BlockImportQueue, PeerBlockSyncer)>,
}

impl<ParentchainBlock, SignedSidechainBlock, BlockImportQueue, PeerBlockSyncer>
	BlockImportQueueWorkerMock<ParentchainBlock, SignedSidechainBlock, BlockImportQueue, PeerBlockSyncer>
where
    ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
    SignedSidechainBlock:
        SignedSidechainBlockTrait<Public = <sp_core::ed25519::Pair as Pair>::Public> + 'static,
	SignedSidechainBlock::Block: BlockTrait,
	BlockImportQueue: PopFromBlockQueue<BlockType = SignedSidechainBlock>,
	PeerBlockSyncer: SyncBlockFromPeer<ParentchainBlock::Header, SignedSidechainBlock>,
{
	pub fn new(
	) -> Self {
		BlockImportQueueWorkerMock {
			_phantom: Default::default(),
		}
	}
}

impl<ParentchainBlock, SignedSidechainBlock, BlockImportQueue, PeerBlockSyncer> Default
	for BlockImportQueueWorkerMock<ParentchainBlock, SignedSidechainBlock, BlockImportQueue, PeerBlockSyncer>
where
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	SignedSidechainBlock:
		SignedSidechainBlockTrait<Public = <sp_core::ed25519::Pair as Pair>::Public> + 'static,
{
	fn default() -> Self {
		BlockImportQueueWorkerMock {
			_phantom: Default::default(),
		}
	}
}

#[test]
fn queue_worker() {
    println!("Hello!!!!!!");
}