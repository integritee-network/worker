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

use crate::{Getter, State, Stf, TrustedCall, TrustedCallSigned};
use ita_sgx_runtime::Runtime;
use itp_node_api::metadata::{metadata_mocks::NodeMetadataMock, provider::NodeMetadataRepository};
use itp_stf_interface::{
	sudo_pallet::SudoPalletInterface, system_pallet::SystemPalletAccountInterface, InitState,
	StateCallInterface,
};
use itp_stf_primitives::types::{AccountId, Signature};
use sp_core::{
	ed25519::{Pair as Ed25519Pair, Signature as Ed25519Signature},
	Pair,
};
use std::{sync::Arc, vec::Vec};

pub type StfState = Stf<TrustedCallSigned, Getter, State, Runtime>;

pub fn enclave_account_initialization_works() {
	let enclave_account = AccountId::new([2u8; 32]);
	let mut state = StfState::init_state(enclave_account.clone());
	let _root = StfState::get_root(&mut state);
	let account_data = StfState::get_account_data(&mut state, &enclave_account);

	assert_eq!(0, StfState::get_account_nonce(&mut state, &enclave_account));
	assert_eq!(enclave_account, StfState::get_enclave_account(&mut state));
	assert_eq!(1000, account_data.free);
}

pub fn shield_funds_increments_signer_account_nonce() {
	let enclave_call_signer = Ed25519Pair::from_seed(b"14672678901234567890123456789012");
	let enclave_signer_account_id: AccountId = enclave_call_signer.public().into();
	let mut state = StfState::init_state(enclave_signer_account_id.clone());

	let shield_funds_call = TrustedCallSigned::new(
		TrustedCall::balance_shield(
			enclave_call_signer.public().into(),
			AccountId::new([1u8; 32]),
			500u128,
		),
		0,
		Signature::Ed25519(Ed25519Signature([0u8; 64])),
	);

	let repo = Arc::new(NodeMetadataRepository::new(NodeMetadataMock::new()));
	StfState::execute_call(&mut state, shield_funds_call, &mut Vec::new(), repo).unwrap();
	assert_eq!(1, StfState::get_account_nonce(&mut state, &enclave_signer_account_id));
}

pub fn test_root_account_exists_after_initialization() {
	let enclave_account = AccountId::new([2u8; 32]);
	let mut state = StfState::init_state(enclave_account);
	let root_account = StfState::get_root(&mut state);

	let account_data = StfState::get_account_data(&mut state, &root_account);
	assert!(account_data.free > 0);
}
