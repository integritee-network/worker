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

//! Utility methods to stringify certain types that don't have a working
//! `Debug` implementation on `sgx`.

use codec::Encode;
use sp_core::{crypto::Public, hexdisplay::HexDisplay};
use std::{format, string::String};

/// Convert a sp_core public type to string.
pub fn public_to_string<T: Public>(t: &T) -> String {
	let crypto_pair = t.as_ref();
	format!("{}", HexDisplay::from(&crypto_pair))
}

pub fn account_id_to_string<AccountId: Encode>(account: &AccountId) -> String {
	format!("{}", HexDisplay::from(&account.encode()))
}
