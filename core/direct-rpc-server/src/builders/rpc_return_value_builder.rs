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

use codec::Encode;
use itp_rpc::RpcReturnValue;
use itp_types::DirectRequestStatus;
use std::{string::String, vec::Vec};

/// Builder pattern for a RpcReturnValue
pub struct RpcReturnValueBuilder {
	maybe_do_watch: Option<bool>,
	maybe_status: Option<DirectRequestStatus>,
	maybe_value: Option<Vec<u8>>,
}

impl RpcReturnValueBuilder {
	#[allow(unused)]
	pub fn new() -> Self {
		RpcReturnValueBuilder { maybe_do_watch: None, maybe_status: None, maybe_value: None }
	}

	#[allow(unused)]
	pub fn with_do_watch(mut self, do_watch: bool) -> Self {
		self.maybe_do_watch = Some(do_watch);
		self
	}

	#[allow(unused)]
	pub fn with_status(mut self, status: DirectRequestStatus) -> Self {
		self.maybe_status = Some(status);
		self
	}

	#[allow(unused)]
	pub fn with_value(mut self, value: Vec<u8>) -> Self {
		self.maybe_value = Some(value);
		self
	}

	#[allow(unused)]
	pub fn build(self) -> RpcReturnValue {
		let do_watch = self.maybe_do_watch.unwrap_or(false);
		let status = self.maybe_status.unwrap_or(DirectRequestStatus::Ok);
		let value = self.maybe_value.unwrap_or(String::from("value").encode());

		RpcReturnValue { value, do_watch, status }
	}
}
