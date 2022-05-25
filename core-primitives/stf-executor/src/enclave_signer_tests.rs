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
	enclave_signer::StfEnclaveSigner, executor_tests::init_state_and_shard_with_state_handler,
	traits::StfEnclaveSigning,
};
use ita_stf::{AccountId, TrustedCall};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_test::mock::{handle_state_mock::HandleStateMock, onchain_mock::OnchainMock};
use sp_core::Pair;
use std::sync::Arc;

pub fn enclave_signer_signatures_are_valid() {
	let ocall_api = Arc::new(OnchainMock::default());
	let state_handler = Arc::new(HandleStateMock::default());
	let signer = sp_core::ed25519::Pair::from_seed(b"61345678901234567890123456789012");
	let (_, shard) = init_state_and_shard_with_state_handler(state_handler.as_ref());
	let mr_enclave = ocall_api.get_mrenclave_of_self().unwrap();

	let enclave_signer = StfEnclaveSigner::new(state_handler, ocall_api, signer);

	let enclave_account = enclave_signer.get_enclave_account();
	let trusted_call =
		TrustedCall::balance_shield(enclave_account, AccountId::new([3u8; 32]), 200u128);

	let trusted_call_signed = enclave_signer.sign_call_with_self(&trusted_call, &shard).unwrap();
	assert!(trusted_call_signed.verify_signature(&mr_enclave.m, &shard));
}
