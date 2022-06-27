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

use crate::ocall_bridge::bridge_api::{OCallBridgeResult, SidechainBridge};

#[derive(Default)]
pub struct SidechainBridgeMock {
	peer_blocks_encoded: Vec<u8>,
}

impl SidechainBridgeMock {
	pub fn with_peer_blocks(mut self, blocks_encoded: Vec<u8>) -> Self {
		self.peer_blocks_encoded = blocks_encoded;
		self
	}
}

impl SidechainBridge for SidechainBridgeMock {
	fn propose_sidechain_blocks(&self, _signed_blocks_encoded: Vec<u8>) -> OCallBridgeResult<()> {
		Ok(())
	}

	fn store_sidechain_blocks(&self, _signed_blocks_encoded: Vec<u8>) -> OCallBridgeResult<()> {
		Ok(())
	}

	fn fetch_sidechain_blocks_from_peer(
		&self,
		_last_imported_block_hash_encoded: Vec<u8>,
		_maybe_until_block_hash_encoded: Vec<u8>,
		_shard_identifier_encoded: Vec<u8>,
	) -> OCallBridgeResult<Vec<u8>> {
		Ok(self.peer_blocks_encoded.clone())
	}
}
