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

use crate::{
	test::mocks::{environment_mock::EnvironmentMock, state_mock::StateMock},
	verifier::AuraVerifier,
	Aura,
};
use itc_parentchain_block_import_dispatcher::trigger_parentchain_block_import_mock::TriggerParentchainBlockImportMock;
use itp_test::mock::onchain_mock::OnchainMock;
use itp_types::Block as ParentchainBlock;
use its_primitives::{
	traits::{
		Block as SidechainBlockTrait, Header as SidechainHeaderTrait,
		SignedBlock as SignedBlockTrait,
	},
	types::block::{Block as SidechainBlock, SignedBlock as SignedSidechainBlock},
};
use sp_runtime::{app_crypto::ed25519, generic::SignedBlock};

type AuthorityPair = ed25519::Pair;

pub type ShardIdentifierFor<SidechainBlock> =
	<<<SidechainBlock as SignedBlockTrait>::Block as SidechainBlockTrait>::HeaderType as SidechainHeaderTrait>::ShardIdentifier;

pub type TestAura = Aura<
	AuthorityPair,
	ParentchainBlock,
	SignedSidechainBlock,
	EnvironmentMock,
	OnchainMock,
	TriggerParentchainBlockImportMock<SignedBlock<ParentchainBlock>>,
>;

pub type TestAuraVerifier = AuraVerifier<
	AuthorityPair,
	ParentchainBlock,
	SignedSidechainBlock,
	StateMock<SidechainBlock>,
	OnchainMock,
>;
