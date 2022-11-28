/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/

use crate::{test::mocks::verifier_mock::VerifierMock, BlockImport, Error, Result};
use core::marker::PhantomData;
use itp_sgx_crypto::aes::Aes;
use itp_sgx_externalities::SgxExternalities;
use itp_test::mock::onchain_mock::OnchainMock;
use itp_types::H256;
use its_primitives::traits::{ShardIdentifierFor, SignedBlock as SignedSidechainBlockTrait};
use sp_core::Pair;
use sp_runtime::traits::Block as ParentchainBlockTrait;
use std::{collections::VecDeque, sync::RwLock};

/// Block importer mock.
pub struct BlockImportMock<ParentchainBlock, SignedSidechainBlock>
where
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	SignedSidechainBlock:
		SignedSidechainBlockTrait<Public = <sp_core::ed25519::Pair as Pair>::Public> + 'static,
{
	import_result: RwLock<VecDeque<Result<ParentchainBlock::Header>>>,
	imported_blocks: RwLock<Vec<SignedSidechainBlock>>,
	_phantom: PhantomData<(ParentchainBlock, SignedSidechainBlock)>,
}

impl<ParentchainBlock, SignedSidechainBlock> BlockImportMock<ParentchainBlock, SignedSidechainBlock>
where
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	SignedSidechainBlock:
		SignedSidechainBlockTrait<Public = <sp_core::ed25519::Pair as Pair>::Public> + 'static,
{
	pub fn with_import_result_once(self, result: Result<ParentchainBlock::Header>) -> Self {
		let mut imported_results_lock = self.import_result.write().unwrap();
		imported_results_lock.push_back(result);
		std::mem::drop(imported_results_lock);
		self
	}

	#[allow(unused)]
	pub fn with_import_result_sequence(
		self,
		mut results: VecDeque<Result<ParentchainBlock::Header>>,
	) -> Self {
		let mut imported_results_lock = self.import_result.write().unwrap();
		imported_results_lock.append(&mut results);
		std::mem::drop(imported_results_lock);
		self
	}

	pub fn get_imported_blocks(&self) -> Vec<SignedSidechainBlock> {
		(*self.imported_blocks.read().unwrap()).clone()
	}
}

impl<ParentchainBlock, SignedSidechainBlock> Default
	for BlockImportMock<ParentchainBlock, SignedSidechainBlock>
where
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	SignedSidechainBlock:
		SignedSidechainBlockTrait<Public = <sp_core::ed25519::Pair as Pair>::Public> + 'static,
{
	fn default() -> Self {
		BlockImportMock {
			import_result: RwLock::default(),
			imported_blocks: RwLock::default(),
			_phantom: Default::default(),
		}
	}
}

impl<ParentchainBlock, SignedSidechainBlock> BlockImport<ParentchainBlock, SignedSidechainBlock>
	for BlockImportMock<ParentchainBlock, SignedSidechainBlock>
where
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	SignedSidechainBlock:
		SignedSidechainBlockTrait<Public = <sp_core::ed25519::Pair as Pair>::Public> + 'static,
{
	type Verifier =
		VerifierMock<ParentchainBlock, SignedSidechainBlock, SignedSidechainBlock, OnchainMock>;
	type SidechainState = SgxExternalities;
	type StateCrypto = Aes;
	type Context = OnchainMock;

	fn verifier(
		&self,
		_maybe_last_sidechain_block: Option<SignedSidechainBlock::Block>,
	) -> Self::Verifier {
		todo!()
	}

	fn apply_state_update<F>(
		&self,
		_shard: &ShardIdentifierFor<SignedSidechainBlock>,
		_mutating_function: F,
	) -> Result<()>
	where
		F: FnOnce(Self::SidechainState) -> Result<Self::SidechainState>,
	{
		todo!()
	}

	fn verify_import<F>(
		&self,
		_shard: &ShardIdentifierFor<SignedSidechainBlock>,
		_verifying_function: F,
	) -> core::result::Result<SignedSidechainBlock, Error>
	where
		F: FnOnce(&Self::SidechainState) -> core::result::Result<SignedSidechainBlock, Error>,
	{
		todo!()
	}

	fn state_key(&self) -> Result<Self::StateCrypto> {
		todo!()
	}

	fn get_context(&self) -> &Self::Context {
		todo!()
	}

	fn import_parentchain_block(
		&self,
		_sidechain_block: &SignedSidechainBlock::Block,
		_last_imported_parentchain_header: &ParentchainBlock::Header,
	) -> Result<ParentchainBlock::Header> {
		todo!()
	}

	fn peek_parentchain_header(
		&self,
		_sidechain_block: &SignedSidechainBlock::Block,
		_last_imported_parentchain_header: &ParentchainBlock::Header,
	) -> core::result::Result<ParentchainBlock::Header, Error> {
		todo!()
	}

	fn cleanup(&self, _signed_sidechain_block: &SignedSidechainBlock) -> Result<()> {
		todo!()
	}

	fn import_block(
		&self,
		signed_sidechain_block: SignedSidechainBlock,
		parentchain_header: &ParentchainBlock::Header,
	) -> Result<ParentchainBlock::Header> {
		let mut imported_blocks_lock = self.imported_blocks.write().unwrap();
		imported_blocks_lock.push(signed_sidechain_block);

		let mut imported_results_lock = self.import_result.write().unwrap();
		imported_results_lock.pop_front().unwrap_or(Ok(parentchain_header.clone()))
	}
}
