/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

use crate::tests::*;
use ita_stf::{
	test_genesis::{endowed_account, second_endowed_account, unendowed_account},
	TrustedCall, TrustedCallSigned, TrustedGetter, TrustedOperation,
};
use itp_sgx_crypto::{Aes, Ed25519Seal, StateCrypto};
use itp_sgx_io::SealedIO;
use itp_stf_executor::executor::StfExecutor;
use itp_stf_state_handler::handle_state::HandleState;
use itp_test::{
	builders::parentchain_header_builder::ParentchainHeaderBuilder,
	mock::{
		handle_state_mock, handle_state_mock::HandleStateMock, onchain_mock::OnchainMock,
		shielding_crypto_mock::ShieldingCryptoMock,
	},
};
use itp_types::{
	AccountId, Block as ParentchainBlock, Header, MrEnclave, OpaqueCall, ShardIdentifier,
};
use its_sidechain::{
	aura::{block_importer::BlockImporter, proposer_factory::ProposerFactory},
	block_composer::{BlockComposer, ComposeBlockAndConfirmation},
	consensus_common::{BlockImport, Environment, Proposer},
	primitives::types::block::{Block as SidechainBlock, SignedBlock as SignedSidechainBlock},
	state::{SidechainDB, SidechainState, SidechainSystemExt},
	top_pool::{basic_pool::BasicPool, pool::ExtrinsicHash},
	top_pool_executor::{TopPoolCallOperator, TopPoolOperationHandler},
	top_pool_rpc_author::{
		api::SidechainApi,
		author::Author,
		author_tests,
		test_utils::{get_pending_tops_separated, submit_operation_to_top_pool},
		top_filter::AllowAllTopsFilter,
	},
};
use sgx_externalities::SgxExternalities;
use sp_core::{crypto::Pair, ed25519 as spEd25519, hashing::blake2_256, H256};
use std::{sync::Arc, time::Duration};

type SidechainStateType = SidechainDB<SidechainBlock, SgxExternalities>;

pub fn upon_proposing_and_importing_sidechain_block_calls_are_removed_from_pool() {
	// given
	let enclave_signer = Ed25519Seal::unseal().unwrap();
	let (rpc_author, _, shard, mrenclave, shielding_key, state_handler) = test_setup();
	let parentchain_header = ParentchainHeaderBuilder::default().build();
	let ocall_api = Arc::new(OnchainMock::default().with_mr_enclave(mrenclave));
	let stf_executor = Arc::new(StfExecutor::new(ocall_api.clone(), state_handler.clone()));
	let top_pool_executor =
		Arc::new(TopPoolOperationHandler::<ParentchainBlock, SignedSidechainBlock, _, _>::new(
			rpc_author.clone(),
			stf_executor.clone(),
		));
	let block_composer =
		Arc::new(BlockComposer::<ParentchainBlock, SignedSidechainBlock, _, _, _>::new(
			enclave_signer.clone(),
			state_key(),
			rpc_author.clone(),
		));
	let proposer = ProposerFactory::new(top_pool_executor.clone(), stf_executor, block_composer)
		.init(parentchain_header.clone(), shard)
		.unwrap();

	let sidechain_block_importer = BlockImporter::<
		_,
		ParentchainBlock,
		SignedSidechainBlock,
		_,
		SidechainStateType,
		_,
		_,
		_,
	>::new(
		state_handler,
		state_key(),
		enclave_signer,
		top_pool_executor.clone(),
		ocall_api,
	);

	// Populate the top-pool.
	let sender = endowed_account();
	let receiver = unfunded_public();
	let signed_call = TrustedCall::balance_transfer(sender.public().into(), receiver.into(), 1000)
		.sign(&sender.clone().into(), 0, &mrenclave, &shard);
	let _top_hash = submit_operation_to_top_pool(
		rpc_author.as_ref(),
		&direct_top(signed_call.clone()),
		&shielding_key,
		shard,
	)
	.unwrap();
	let sender_two = second_endowed_account();
	let signed_call_two = TrustedCall::balance_transfer(
		sender_two.public().into(),
		receiver.into(),
		1000,
	)
	.sign(&sender_two.clone().into(), 0, &mrenclave, &shard);
	let _top_hash_two = submit_operation_to_top_pool(
		rpc_author.as_ref(),
		&direct_top(signed_call_two.clone()),
		&shielding_key,
		shard,
	)
	.unwrap();

	// Propose a sidechain block.
	let enough_execution_time = Duration::from_secs(10000);
	let proposed_block: SignedSidechainBlock =
		proposer.propose(enough_execution_time).unwrap().block;

	// Ensure that after proposing calls have not yet been removed.
	let retrieved_trusted_calls = top_pool_executor.as_ref().get_trusted_calls(&shard).unwrap();
	assert!(retrieved_trusted_calls.contains(&signed_call));
	assert!(retrieved_trusted_calls.contains(&signed_call_two));

	// Import the proposed sidechain block.
	sidechain_block_importer
		.import_block(proposed_block, &parentchain_header)
		.unwrap();

	// then
	let retrieved_trusted_calls = top_pool_executor.as_ref().get_trusted_calls(&shard).unwrap();
	assert!(retrieved_trusted_calls.is_empty());
}
