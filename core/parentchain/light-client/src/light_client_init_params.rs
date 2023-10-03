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
use sp_consensus_grandpa::AuthorityList;
use std::vec::Vec;

#[derive(Encode, Decode, Clone)]
pub struct GrandpaParams<Header> {
	pub genesis_header: Header,
	pub authorities: AuthorityList,
	pub authority_proof: Vec<Vec<u8>>,
}

impl<Header> GrandpaParams<Header> {
	pub fn new(
		genesis_header: Header,
		authorities: AuthorityList,
		authority_proof: Vec<Vec<u8>>,
	) -> Self {
		Self { genesis_header, authorities, authority_proof }
	}
}

#[derive(Encode, Decode, Clone)]
pub struct SimpleParams<Header> {
	pub genesis_header: Header,
}

impl<Header> SimpleParams<Header> {
	pub fn new(genesis_header: Header) -> Self {
		Self { genesis_header }
	}
}
