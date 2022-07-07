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

use crate::test::tests_main::test_setup;
use core::str::FromStr;
use ita_stf::{
	test_genesis::{endow, endowed_account as funded_pair},
	Stf, TrustedCall,
};
use itp_types::AccountId;
use sgx_runtime::AddressMapping;
use sp_core::{crypto::Pair, H160, U256};
use std::vec::Vec;

pub fn test_evm_call() {
	// given
	let (_, mut state, shard, mrenclave, _, _) = test_setup();
	let mut opaque_vec = Vec::new();

	let sender = funded_pair();
	let sender_acc: AccountId = sender.public().into();

	let mut sender_evm_acc_slice: [u8; 20] = [0; 20];
	sender_evm_acc_slice
		.copy_from_slice((<[u8; 32]>::from(sender_acc.clone())).get(0..20).unwrap());
	let sender_evm_acc: H160 = sender_evm_acc_slice.into();

	// Ensure the substrate version of the evm account has some money.
	let sender_evm_substrate_addr =
		sgx_runtime::HashedAddressMapping::into_account_id(sender_evm_acc);
	endow(&mut state, vec![(sender_evm_substrate_addr, 21_777_000_000_000, 0)]);

	let trusted_call = TrustedCall::evm_call(
		sender_acc,
		sender_evm_acc,
		H160::from_str("1000000000000000000000000000000000000001").unwrap(),
		Vec::new(),
		U256::from(1_000_000_000),
		21776,
		U256::from(1_000_000_000),
		None,
		Some(U256::from(0)),
		Vec::new(),
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	let result = Stf::execute(&mut state, trusted_call, &mut opaque_vec).unwrap();
}
