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

use crate::AuraVerifier;
use core::marker::PhantomData;
use itp_sgx_crypto::aes::Aes;
use itp_test::mock::onchain_mock::OnchainMock;
use itp_types::H256;
use its_consensus_common::{BlockImport, Error, Result};
use its_primitives::traits::{ShardIdentifierFor, SignedBlock as SignedSidechainBlockTrait};
use its_state::SidechainDB;
use sgx_externalities::SgxExternalities;
use sp_core::Pair;
use sp_runtime::traits::Block as ParentchainBlockTrait;

pub struct BlockImportMock<ParentchainBlock, SignedSidechainBlock> {
	_phantom: PhantomData<(ParentchainBlock, SignedSidechainBlock)>,
}

impl<ParentchainBlock, SignedSidechainBlock> BlockImport<ParentchainBlock, SignedSidechainBlock>
	for BlockImportMock<ParentchainBlock, SignedSidechainBlock>
where
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	SignedSidechainBlock:
		SignedSidechainBlockTrait<Public = <sp_core::ed25519::Pair as Pair>::Public> + 'static,
{
	type Verifier = AuraVerifier<
		sp_core::ed25519::Pair,
		ParentchainBlock,
		SignedSidechainBlock,
		SidechainDB<SignedSidechainBlock::Block, SgxExternalities>,
		OnchainMock,
	>;
	type SidechainState = SidechainDB<SignedSidechainBlock::Block, SgxExternalities>;
	type StateCrypto = Aes;
	type Context = OnchainMock;

	fn verifier(&self, _state: Self::SidechainState) -> Self::Verifier {
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

	fn state_key(&self) -> Self::StateCrypto {
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

	fn cleanup(&self, _signed_sidechain_block: &SignedSidechainBlock) -> Result<()> {
		todo!()
	}

	fn handle_import_error(
		&self,
		_signed_sidechain_block: &SignedSidechainBlock,
		_error: Error,
	) -> Result<()> {
		todo!()
	}

	fn import_block(
		&self,
		_signed_sidechain_block: SignedSidechainBlock,
		_parentchain_header: &ParentchainBlock::Header,
	) -> Result<()> {
		todo!()
	}
}
