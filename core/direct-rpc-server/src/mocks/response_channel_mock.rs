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

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::{response_channel::ResponseChannel, DirectRpcError};
use std::vec::Vec;

#[derive(Default)]
pub struct ResponseChannelMock<Token>
where
	Token: Copy + Send + Sync,
{
	sent_messages: RwLock<Vec<(Token, String)>>,
}

impl<Token> ResponseChannelMock<Token>
where
	Token: Copy + Send + Sync,
{
	pub fn number_of_updates(&self) -> usize {
		self.sent_messages.read().unwrap().len()
	}
}

impl<Token> ResponseChannel<Token> for ResponseChannelMock<Token>
where
	Token: Copy + Send + Sync,
{
	type Error = DirectRpcError;

	fn respond(&self, token: Token, message: String) -> Result<(), Self::Error> {
		let mut messages_lock = self.sent_messages.write().unwrap();
		messages_lock.push((token, message));
		Ok(())
	}
}
