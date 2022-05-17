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

use codec::{Decode, Encode};
use sp_finality_grandpa::AuthorityList;
use sp_std::vec::Vec;

// The variants will be chosen according to availability of grandpa authorities on the parent chain.
#[derive(Encode, Decode)]
pub enum LightClientInitParams<Header> {
	Grandpa { genesis_header: Header, authorities: AuthorityList, authority_proof: Vec<Vec<u8>> },
}

impl<Header> LightClientInitParams<Header> {
	pub fn get_authorities(self) -> AuthorityList {
		match self {
			LightClientInitParams::Grandpa { authorities, .. } => authorities,
		}
	}

	pub fn get_genesis_header(self) -> Header {
		match self {
			LightClientInitParams::Grandpa { genesis_header, .. } => genesis_header,
		}
	}
}
