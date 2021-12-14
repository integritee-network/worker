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

use ita_stf::{Getter, KeyPair, TrustedGetter};
use serde_derive::{Deserialize, Serialize};
use sgx_types::*;
use sp_keyring::AccountKeyring;
use std::str;

#[cfg(test)]
use crate::config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
	pub account: String,
	pub amount: u32,
	pub sha256: sgx_sha256_hash_t,
}

pub fn test_trusted_getter_signed(who: AccountKeyring) -> Getter {
	let getter = TrustedGetter::free_balance(who.public().into());
	Getter::trusted(getter.sign(&KeyPair::Sr25519(who.pair())))
}

/// Local Worker config. Fields are the default values except for
/// the worker's rpc server.
#[cfg(test)]
pub fn local_worker_config(worker_url: String) -> Config {
	let mut url = worker_url.split(":");
	Config::new(
		Default::default(),
		Default::default(),
		url.next().unwrap().into(),
		url.next().unwrap().into(),
		Default::default(),
	)
}
