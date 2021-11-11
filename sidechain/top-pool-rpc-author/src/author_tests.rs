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
	author::Author,
	test_utils::submit_operation_to_top_pool,
	top_filter::{AllowAllTopsFilter, Filter, GettersOnlyFilter},
};
use codec::{Decode, Encode};
use ita_stf::{
	Getter, KeyPair, ShardIdentifier, TrustedCall, TrustedCallSigned, TrustedGetter,
	TrustedOperation,
};
use itp_sgx_crypto::ShieldingCrypto;
use itp_stf_state_handler::handle_state::HandleState;
use itp_test::mock::{
	handle_state_mock::HandleStateMock, shielding_crypto_mock::ShieldingCryptoMock,
	trusted_operation_pool_mock::TrustedOperationPoolMock,
};
use sgx_crypto_helper::{rsa3072::Rsa3072KeyPair, RsaKeyPair};
use sp_core::{ed25519, Pair, H256};
use sp_runtime::traits::{BlakeTwo256, Hash};
use std::{sync::Arc, vec};

type Seed = [u8; 32];
const TEST_SEED: Seed = *b"12345678901234567890123456789012";

type TestAuthor<F> = Author<TrustedOperationPoolMock, F, HandleStateMock, ShieldingCryptoMock>;

pub fn top_encryption_works() {
	// the sgx crypto crate lacks unit tests, one of the reasons being that the
	// crypto structs are only available in SGX mode and cannot be tested using cargo test
	// so we test some of the functionality here, where we encrypt and decrypt trusted operations
	// using a RSA3072 key

	let trusted_call = TrustedOperation::from(trusted_call_signed());
	let trusted_getter = TrustedOperation::from(trusted_getter_signed());

	assert_eq!(trusted_call, encrypt_and_decrypt_top(&trusted_call));
	assert_eq!(trusted_getter, encrypt_and_decrypt_top(&trusted_getter));
}

fn encrypt_and_decrypt_top(top: &TrustedOperation) -> TrustedOperation {
	let encryption_key = Rsa3072KeyPair::new().unwrap();
	let encrypted_top = encryption_key.encrypt(top.encode().as_slice()).unwrap();
	let decrypted_top = encryption_key.decrypt(encrypted_top.as_slice()).unwrap();

	TrustedOperation::decode(&mut decrypted_top.as_slice()).unwrap()
}

pub fn submitting_to_author_inserts_in_pool() {
	let (author, top_pool, shielding_key) = create_author_with_filter(AllowAllTopsFilter);
	let top = TrustedOperation::from(trusted_getter_signed());

	let submit_response: H256 =
		submit_operation_to_top_pool(&author, &top, &shielding_key, shard_id()).unwrap();

	assert!(!submit_response.is_zero());

	let submitted_transactions = top_pool.get_last_submitted_transactions();
	assert_eq!(1, submitted_transactions.len());
}

pub fn submitting_call_to_author_when_top_is_filtered_returns_error() {
	let (author, top_pool, shielding_key) = create_author_with_filter(GettersOnlyFilter);
	let top = TrustedOperation::from(trusted_call_signed());

	let submit_response = submit_operation_to_top_pool(&author, &top, &shielding_key, shard_id());

	assert!(submit_response.is_err());
	assert!(top_pool.get_last_submitted_transactions().is_empty());
}

pub fn submitting_getter_to_author_when_top_is_filtered_inserts_in_pool() {
	let (author, top_pool, shielding_key) = create_author_with_filter(GettersOnlyFilter);
	let top = TrustedOperation::from(trusted_getter_signed());

	let submit_response =
		submit_operation_to_top_pool(&author, &top, &shielding_key, shard_id()).unwrap();

	assert!(!submit_response.is_zero());
	assert_eq!(1, top_pool.get_last_submitted_transactions().len());
}

fn create_author_with_filter<F: Filter<Value = TrustedOperation>>(
	filter: F,
) -> (TestAuthor<F>, Arc<TrustedOperationPoolMock>, ShieldingCryptoMock) {
	let top_pool = Arc::new(TrustedOperationPoolMock::default());

	let shard_id = shard_id();
	let state_facade = HandleStateMock::default();
	let _ = state_facade.load_initialized(&shard_id).unwrap();

	let encryption_key = ShieldingCryptoMock::default();

	(
		Author::new(top_pool.clone(), filter, Arc::new(state_facade), encryption_key.clone()),
		top_pool,
		encryption_key,
	)
}

fn trusted_call_signed() -> TrustedCallSigned {
	let account = ed25519::Pair::from_seed(&TEST_SEED);
	let call =
		TrustedCall::balance_shield(account.public().into(), account.public().into(), 12u128);
	call.sign(&KeyPair::Ed25519(account), 0, &mr_enclave(), &shard_id())
}

fn trusted_getter_signed() -> Getter {
	let account = ed25519::Pair::from_seed(&TEST_SEED);
	let getter = TrustedGetter::free_balance(account.public().into());
	Getter::trusted(getter.sign(&KeyPair::Ed25519(account)))
}

fn mr_enclave() -> [u8; 32] {
	[1u8; 32]
}

fn shard_id() -> ShardIdentifier {
	BlakeTwo256::hash(vec![1u8, 2u8, 3u8].as_slice().encode().as_slice())
}
