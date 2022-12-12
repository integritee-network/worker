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

use itp_time_utils::now_as_millis;
use itp_types::{EnclaveGen, PalletString};

/// Builder for a generic enclave (`EnclaveGen`) struct.
pub struct EnclaveGenBuilder<AccountId> {
	pubkey: AccountId,
	mr_enclave: [u8; 32],
	timestamp: u64,
	url: PalletString, // utf8 encoded url
}

impl<AccountId> Default for EnclaveGenBuilder<AccountId>
where
	AccountId: Default,
{
	fn default() -> Self {
		EnclaveGenBuilder {
			pubkey: AccountId::default(),
			mr_enclave: [0u8; 32],
			timestamp: now_as_millis(),
			url: PalletString::default(),
		}
	}
}

impl<AccountId> EnclaveGenBuilder<AccountId> {
	pub fn with_account(mut self, account: AccountId) -> Self {
		self.pubkey = account;
		self
	}

	pub fn with_url(mut self, url: PalletString) -> Self {
		self.url = url;
		self
	}

	pub fn build(self) -> EnclaveGen<AccountId> {
		EnclaveGen {
			pubkey: self.pubkey,
			mr_enclave: self.mr_enclave,
			timestamp: self.timestamp,
			url: self.url,
		}
	}
}
