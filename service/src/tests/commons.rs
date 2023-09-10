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

use serde_derive::{Deserialize, Serialize};
use sgx_types::*;
use std::str;

#[cfg(test)]
use crate::config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
	pub account: String,
	pub amount: u32,
	pub sha256: sgx_sha256_hash_t,
}

#[cfg(test)]
pub fn local_worker_config(
	worker_url: String,
	untrusted_worker_port: String,
	mu_ra_port: String,
) -> Config {
	let mut url = worker_url.split(':');

	Config::new(
		Default::default(),
		Default::default(),
		Default::default(),
		Default::default(),
		Default::default(),
		Default::default(),
		url.next().unwrap().into(),
		None,
		url.next().unwrap().into(),
		None,
		untrusted_worker_port,
		None,
		mu_ra_port,
		false,
		"8787".to_string(),
		"4545".to_string(),
		crate::config::pwd(),
		None,
	)
}
