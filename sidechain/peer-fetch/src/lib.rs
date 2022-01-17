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

#![cfg_attr(not(feature = "std"), no_std)]

pub mod block_fetch_client;
pub mod block_fetch_server;
pub mod error;
pub mod untrusted_peer_fetch;

#[cfg(feature = "mocks")]
pub mod mocks;

use crate::error::Result;
use async_trait::async_trait;
use its_primitives::{
	traits::SignedBlock,
	types::{BlockHash, ShardIdentifier},
};
use std::vec::Vec;

/// Trait to fetch block from peer validateers.
///
/// This is used by an outdated validateer to get the most recent state.
#[async_trait]
pub trait FetchBlocksFromPeer {
	type SignedBlockType: SignedBlock;

	async fn fetch_blocks_from_peer(
		&self,
		last_known_block_hash: BlockHash,
		shard_identifier: ShardIdentifier,
	) -> Result<Vec<Self::SignedBlockType>>;
}
