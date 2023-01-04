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

use ita_sgx_runtime::Runtime;
use ita_stf::{Stf, TrustedCall};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_sgx_crypto::{
	ed25519_derivation::DeriveEd25519, key_repository::AccessKey, mocks::KeyRepositoryMock,
};
use itp_sgx_externalities::SgxExternalities;
use itp_stf_executor::{enclave_signer::StfEnclaveSigner, traits::StfEnclaveSigning};
use itp_stf_interface::{
	mocks::{CallExecutorMock, GetterExecutorMock},
	InitState,
};
use itp_stf_primitives::types::{AccountId, ShardIdentifier};
use itp_stf_state_observer::mock::ObserveStateMock;
use itp_test::mock::onchain_mock::OnchainMock;
use itp_top_pool_author::mocks::AuthorApiMock;
use sgx_crypto_helper::{rsa3072::Rsa3072KeyPair, RsaKeyPair};
use sp_core::Pair;
use std::sync::Arc;

type ShieldingKeyRepositoryMock = KeyRepositoryMock<Rsa3072KeyPair>;
type TestStf = Stf<CallExecutorMock, GetterExecutorMock, SgxExternalities, Runtime>;

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
