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

use crate::{Result, ShardIdentifierFor, Verifier};
use itp_types::H256;
use its_primitives::traits::SignedBlock as SignedSidechainBlockTrait;
use sp_core::Pair;
use sp_runtime::traits::Block as ParentchainBlockTrait;
use std::marker::PhantomData;

/// Verifier mock implementation.
pub struct VerifierMock<
	ParentchainBlock,
	SignedSidechainBlock,
	BlockImportParameters,
	VerifierContext,
> {
	_phantom: PhantomData<(
		ParentchainBlock,
		SignedSidechainBlock,
		BlockImportParameters,
		VerifierContext,
	)>,
}

impl<ParentchainBlock, SignedSidechainBlock, BlockImportParameters, VerifierContext>
	Verifier<ParentchainBlock, SignedSidechainBlock>
	for VerifierMock<ParentchainBlock, SignedSidechainBlock, BlockImportParameters, VerifierContext>
where
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	SignedSidechainBlock:
		SignedSidechainBlockTrait<Public = <sp_core::ed25519::Pair as Pair>::Public> + 'static,
	BlockImportParameters: Send + Sync,
	VerifierContext: Send + Sync,
{
	type BlockImportParams = BlockImportParameters;
	type Context = VerifierContext;

	fn verify(
		&self,
		_block: SignedSidechainBlock,
		_parentchain_header: &ParentchainBlock::Header,
		_shard: ShardIdentifierFor<SignedSidechainBlock>,
		_ctx: &Self::Context,
	) -> Result<Self::BlockImportParams> {
		todo!()
	}
}
