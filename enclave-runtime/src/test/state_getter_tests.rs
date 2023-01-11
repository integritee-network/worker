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

use codec::Decode;
use ita_sgx_runtime::Runtime;
use ita_stf::{
	test_genesis::{endowed_account, test_genesis_setup, ENDOWED_ACC_FUNDS},
	Balance, Getter, Stf, TrustedCallSigned, TrustedGetter,
};
use itp_sgx_externalities::SgxExternalities;
use itp_stf_executor::state_getter::{GetState, StfStateGetter};
use sp_core::Pair;

type TestState = SgxExternalities;
type TestStf = Stf<TrustedCallSigned, Getter, TestState, Runtime>;
type TestStfStateGetter = StfStateGetter<TestStf>;

pub fn state_getter_works() {
	let sender = endowed_account();
	let signed_getter = TrustedGetter::free_balance(sender.public().into()).sign(&sender.into());
	let mut state = test_state();

	let encoded_balance = TestStfStateGetter::get_state(signed_getter.into(), &mut state)
		.unwrap()
		.unwrap();

	let balance = Balance::decode(&mut encoded_balance.as_slice()).unwrap();

	assert_eq!(balance, ENDOWED_ACC_FUNDS);
}

fn test_state() -> TestState {
	let mut state = TestState::default();
	test_genesis_setup(&mut state);
	state
}
