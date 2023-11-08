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
	test_fixtures::shard_id,
	test_utils::submit_operation_to_top_pool,
	top_filter::{AllowAllTopsFilter, Filter, GettersOnlyFilter},
	traits::AuthorApi,
};
use codec::{Decode, Encode};
use itp_sgx_crypto::{mocks::KeyRepositoryMock, ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};

use itp_stf_state_handler::handle_state::HandleState;
use itp_test::mock::{
	handle_state_mock::HandleStateMock,
	metrics_ocall_mock::MetricsOCallMock,
	shielding_crypto_mock::ShieldingCryptoMock,
	stf_mock::{
		mock_top_direct_trusted_call_signed, mock_top_indirect_trusted_call_signed,
		mock_top_trusted_getter_signed, GetterMock, TrustedCallSignedMock, TrustedOperationMock,
	},
};
use itp_top_pool::mocks::trusted_operation_pool_mock::TrustedOperationPoolMock;

use sgx_crypto_helper::{rsa3072::Rsa3072KeyPair, RsaKeyPair};
use sp_core::H256;
use std::sync::Arc;

type TestAuthor<Filter> = Author<
	TrustedOperationPoolMock<TrustedOperationMock>,
	Filter,
	HandleStateMock,
	KeyRepositoryMock<ShieldingCryptoMock>,
	MetricsOCallMock,
	TrustedCallSignedMock,
	GetterMock,
>;

#[test]
fn top_encryption_works() {
	let top_call = mock_top_direct_trusted_call_signed();
	let top_getter = mock_top_trusted_getter_signed();
	assert_eq!(top_call, encrypt_and_decrypt_top(&top_call));
	assert_eq!(top_getter, encrypt_and_decrypt_top(&top_getter));
}

fn encrypt_and_decrypt_top(top: &TrustedOperationMock) -> TrustedOperationMock {
	let encryption_key = Rsa3072KeyPair::new().unwrap();
	let encrypted_top = encryption_key.encrypt(top.encode().as_slice()).unwrap();
	let decrypted_top = encryption_key.decrypt(encrypted_top.as_slice()).unwrap();

	TrustedOperationMock::decode(&mut decrypted_top.as_slice()).unwrap()
}

#[test]
fn submitting_to_author_inserts_in_pool() {
	let (author, top_pool, shielding_key) = create_author_with_filter(AllowAllTopsFilter::new());
	let top_getter = mock_top_trusted_getter_signed();

	let submit_response: H256 =
		submit_operation_to_top_pool(&author, &top_getter, &shielding_key, shard_id()).unwrap();

	assert!(!submit_response.is_zero());

	let submitted_transactions = top_pool.get_last_submitted_transactions();
	assert_eq!(1, submitted_transactions.len());
}

#[test]
fn submitting_call_to_author_when_top_is_filtered_returns_error() {
	let (author, top_pool, shielding_key) = create_author_with_filter(GettersOnlyFilter::new());
	let top_call = mock_top_direct_trusted_call_signed();
	let submit_response =
		submit_operation_to_top_pool(&author, &top_call, &shielding_key, shard_id());

	assert!(submit_response.is_err());
	assert!(top_pool.get_last_submitted_transactions().is_empty());
}

#[test]
fn submitting_getter_to_author_when_top_is_filtered_inserts_in_pool() {
	let (author, top_pool, shielding_key) = create_author_with_filter(GettersOnlyFilter::new());

	let top_getter = mock_top_trusted_getter_signed();
	let submit_response =
		submit_operation_to_top_pool(&author, &top_getter, &shielding_key, shard_id()).unwrap();

	assert!(!submit_response.is_zero());
	assert_eq!(1, top_pool.get_last_submitted_transactions().len());
}

#[test]
fn submitting_direct_call_works() {
	let (author, top_pool, shielding_key) = create_author_with_filter(AllowAllTopsFilter::new());
	let top_call = mock_top_direct_trusted_call_signed();
	let _ = submit_operation_to_top_pool(&author, &top_call, &shielding_key, shard_id()).unwrap();

	assert_eq!(1, top_pool.get_last_submitted_transactions().len());
	assert_eq!(1, author.get_pending_trusted_calls(shard_id()).len());
}

#[test]
fn submitting_indirect_call_works() {
	let (author, top_pool, shielding_key) = create_author_with_filter(AllowAllTopsFilter::new());
	let top_call = mock_top_indirect_trusted_call_signed();

	let _ = submit_operation_to_top_pool(&author, &top_call, &shielding_key, shard_id()).unwrap();

	assert_eq!(1, top_pool.get_last_submitted_transactions().len());
	assert_eq!(1, author.get_pending_trusted_calls(shard_id()).len());
}

fn create_author_with_filter<F: Filter<Value = TrustedOperationMock>>(
	filter: F,
) -> (TestAuthor<F>, Arc<TrustedOperationPoolMock<TrustedOperationMock>>, ShieldingCryptoMock) {
	let top_pool = Arc::new(TrustedOperationPoolMock::default());

	let shard_id = shard_id();
	let state_facade = HandleStateMock::from_shard(shard_id).unwrap();
	state_facade.load_cloned(&shard_id).unwrap();

	let encryption_key = ShieldingCryptoMock::default();
	let shielding_key_repo =
		Arc::new(KeyRepositoryMock::<ShieldingCryptoMock>::new(encryption_key.clone()));
	let ocall_mock = Arc::new(MetricsOCallMock::default());

	(
		Author::new(
			top_pool.clone(),
			filter,
			Arc::new(state_facade),
			shielding_key_repo,
			ocall_mock,
		),
		top_pool,
		encryption_key,
	)
}
