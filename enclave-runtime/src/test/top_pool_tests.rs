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

use crate::test::{
	fixtures::{
		components::{
			create_ocall_api, create_top_pool, encrypt_trusted_operation, sign_trusted_call,
		},
		initialize_test_state::init_state,
	},
	mocks::types::{
		TestShieldingKey, TestShieldingKeyRepo, TestSigner, TestStateHandler, TestTopPoolAuthor,
	},
};
use ita_stf::{
	test_genesis::{endowed_account, unendowed_account},
	TrustedCall, TrustedOperation,
};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_sgx_crypto::ShieldingCryptoEncrypt;
use itp_test::mock::metrics_ocall_mock::MetricsOCallMock;
use itp_top_pool_author::{author::AuthorTopFilter, traits::AuthorApi};
use itp_types::ShardIdentifier;
use jsonrpc_core::futures::executor;
use log::*;
use sgx_crypto_helper::RsaKeyPair;
use sp_core::Pair;
use std::{sync::Arc, vec::Vec};

pub fn process_indirect_call_in_top_pool() {
	let _ = env_logger::builder().is_test(true).try_init();
	info!("Setting up test.");

	let signer = TestSigner::from_seed(b"42315678901234567890123456789012");
	let shielding_key = TestShieldingKey::new().unwrap();
	let shielding_key_repo = Arc::new(TestShieldingKeyRepo::new(shielding_key));

	let ocall_api = create_ocall_api(&signer);

	let state_handler = Arc::new(TestStateHandler::default());
	let (_, shard_id) = init_state(state_handler.as_ref());

	let top_pool = create_top_pool();

	let top_pool_author = Arc::new(TestTopPoolAuthor::new(
		top_pool,
		AuthorTopFilter {},
		state_handler.clone(),
		shielding_key_repo,
		Arc::new(MetricsOCallMock {}),
	));

	let encrypted_indirect_call =
		encrypted_indirect_call(ocall_api.as_ref(), &shard_id, &shielding_key);

	executor::block_on(top_pool_author.submit_top(encrypted_indirect_call, shard_id)).unwrap();

	assert_eq!(1, top_pool_author.get_pending_tops_separated(shard_id).unwrap().0.len());
}

fn encrypted_indirect_call<
	AttestationApi: EnclaveAttestationOCallApi,
	ShieldingKey: ShieldingCryptoEncrypt,
>(
	attestation_api: &AttestationApi,
	shard_id: &ShardIdentifier,
	shielding_key: &ShieldingKey,
) -> Vec<u8> {
	let sender = endowed_account();
	let receiver = unendowed_account();

	let call =
		TrustedCall::balance_transfer(sender.public().into(), receiver.public().into(), 10000u128);
	let call_signed = sign_trusted_call(&call, attestation_api, shard_id, sender);
	let trusted_operation = TrustedOperation::indirect_call(call_signed);
	encrypt_trusted_operation(shielding_key, &trusted_operation)
}
