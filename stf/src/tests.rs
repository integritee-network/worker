/*
	Copyright 2019 Supercomputing Systems AG

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
use alloc::prelude::v1::Vec;
use crate::{TrustedCall, TrustedGetter, AccountId};
use codec::{Compact, Decode, Encode};


pub fn get_test_balance_set_balance_call() -> Vec<u8> {
    TrustedCall::balance_set_balance(AccountId::default(), 33,44).encode()
}

pub fn get_test_getter_free_balance() -> Vec<u8> {
	TrustedGetter::free_balance(AccountId::default()).encode()
}