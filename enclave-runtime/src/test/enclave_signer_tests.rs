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

use codec::Encode;
use ita_sgx_runtime::Runtime;
use ita_stf::{Stf, TrustedCall, TrustedCallSigned, TrustedOperation};
use itp_node_api::metadata::{metadata_mocks::NodeMetadataMock, provider::NodeMetadataRepository};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_sgx_crypto::{
	ed25519_derivation::DeriveEd25519, key_repository::AccessKey, mocks::KeyRepositoryMock,
};
use itp_sgx_externalities::SgxExternalities;
use itp_stf_executor::{enclave_signer::StfEnclaveSigner, traits::StfEnclaveSigning};
use itp_stf_interface::{
	mocks::GetterExecutorMock, system_pallet::SystemPalletAccountInterface, InitState,
	StateCallInterface,
};
use itp_stf_primitives::types::{AccountId, ShardIdentifier};
use itp_stf_state_observer::mock::ObserveStateMock;
use itp_test::mock::onchain_mock::OnchainMock;
use itp_top_pool_author::{mocks::AuthorApiMock, traits::AuthorApi};
use sgx_crypto_helper::{rsa3072::Rsa3072KeyPair, RsaKeyPair};
use sp_core::Pair;
use std::{sync::Arc, vec::Vec};

type ShieldingKeyRepositoryMock = KeyRepositoryMock<Rsa3072KeyPair>;
type TestStf = Stf<TrustedCallSigned, GetterExecutorMock, SgxExternalities, Runtime>;

pub fn derive_key_is_deterministic() {
	let rsa_key = Rsa3072KeyPair::new().unwrap();

	let first_ed_key = rsa_key.derive_ed25519().unwrap();
	let second_ed_key = rsa_key.derive_ed25519().unwrap();
	assert_eq!(first_ed_key.public(), second_ed_key.public());
}

pub fn enclave_signer_signatures_are_valid() {
	let top_pool_author = Arc::new(AuthorApiMock::default());
	let ocall_api = Arc::new(OnchainMock::default());
	let shielding_key_repo = Arc::new(ShieldingKeyRepositoryMock::default());
	let enclave_account: AccountId = shielding_key_repo
		.retrieve_key()
		.unwrap()
		.derive_ed25519()
		.unwrap()
		.public()
		.into();

	let state_observer: Arc<ObserveStateMock<SgxExternalities>> =
		Arc::new(ObserveStateMock::new(TestStf::init_state(enclave_account.clone())));
	let shard = ShardIdentifier::default();
	let mr_enclave = ocall_api.get_mrenclave_of_self().unwrap();
	let enclave_signer = StfEnclaveSigner::<_, _, _, TestStf, _>::new(
		state_observer,
		ocall_api,
		shielding_key_repo,
		top_pool_author,
	);
	let trusted_call =
		TrustedCall::balance_shield(enclave_account, AccountId::new([3u8; 32]), 200u128);

	let trusted_call_signed = enclave_signer.sign_call_with_self(&trusted_call, &shard).unwrap();
	assert!(trusted_call_signed.verify_signature(&mr_enclave.m, &shard));
}

pub fn nonce_is_computed_correctly() {
	let top_pool_author = Arc::new(AuthorApiMock::default());
	let ocall_api = Arc::new(OnchainMock::default());
	let shielding_key_repo = Arc::new(ShieldingKeyRepositoryMock::default());
	let enclave_account: AccountId = shielding_key_repo
		.retrieve_key()
		.unwrap()
		.derive_ed25519()
		.unwrap()
		.public()
		.into();
	let mut state = TestStf::init_state(enclave_account.clone());
	// only used to create the enclave signer, the state is **not** synchronised
	let state_observer: Arc<ObserveStateMock<SgxExternalities>> =
		Arc::new(ObserveStateMock::new(state.clone()));
	let shard = ShardIdentifier::default();
	let enclave_signer = StfEnclaveSigner::<_, _, _, TestStf, _>::new(
		state_observer,
		ocall_api,
		shielding_key_repo,
		top_pool_author.clone(),
	);

	// create the first trusted_call and submit it
	let trusted_call_1 =
		TrustedCall::balance_shield(enclave_account.clone(), AccountId::new([1u8; 32]), 100u128);
	let trusted_call_1_signed =
		enclave_signer.sign_call_with_self(&trusted_call_1, &shard).unwrap();
	top_pool_author
		.submit_top(TrustedOperation::indirect_call(trusted_call_1_signed.clone()).encode(), shard);
	assert_eq!(1, top_pool_author.get_pending_trusted_calls_for(shard, &enclave_account).len());

	// create the second trusted_call and submit it
	let trusted_call_2 =
		TrustedCall::balance_shield(enclave_account.clone(), AccountId::new([2u8; 32]), 200u128);
	let trusted_call_2_signed =
		enclave_signer.sign_call_with_self(&trusted_call_2, &shard).unwrap();
	top_pool_author
		.submit_top(TrustedOperation::indirect_call(trusted_call_2_signed.clone()).encode(), shard);
	assert_eq!(2, top_pool_author.get_pending_trusted_calls_for(shard, &enclave_account).len());
	// there should be no pending trusted calls for non-enclave-account
	assert_eq!(
		0,
		top_pool_author
			.get_pending_trusted_calls_for(shard, &AccountId::new([1u8; 32]))
			.len()
	);

	assert_eq!(0, TestStf::get_account_nonce(&mut state, &enclave_account));
	let repo = Arc::new(NodeMetadataRepository::new(NodeMetadataMock::new()));
	assert!(TestStf::execute_call(
		&mut state,
		trusted_call_1_signed,
		&mut Vec::new(),
		repo.clone()
	)
	.is_ok());
	assert!(TestStf::execute_call(&mut state, trusted_call_2_signed, &mut Vec::new(), repo).is_ok());
	assert_eq!(2, TestStf::get_account_nonce(&mut state, &enclave_account));
}
