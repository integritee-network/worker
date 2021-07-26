/*
	Copyright 2019 Supercomputing Systems AG
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

use crate::{
	error::Error,
	globals::{tokio_handle::GetTokioHandle, worker::GetWorker},
	worker::{WorkerResult, WorkerT},
};
use log::*;
use std::sync::Arc;
use substratee_worker_primitives::block::SignedBlock as SignedSidechainBlock;

#[cfg(test)]
use mockall::predicate::*;
#[cfg(test)]
use mockall::*;

/// Allows to gossip blocks, does it in a synchronous (i.e. blocking) manner
#[cfg_attr(test, automock)]
pub trait GossipBlocks {
	fn gossip_blocks(&self, blocks: Vec<SignedSidechainBlock>) -> WorkerResult<()>;
}

pub struct SyncBlockGossiper<T, W> {
	tokio_handle: Arc<T>,
	worker: Arc<W>,
}

impl<T, W> SyncBlockGossiper<T, W> {
	pub fn new(tokio_handle: Arc<T>, worker: Arc<W>) -> Self {
		SyncBlockGossiper { tokio_handle, worker }
	}
}

impl<T, W> GossipBlocks for SyncBlockGossiper<T, W>
where
	T: GetTokioHandle,
	W: GetWorker,
{
	fn gossip_blocks(&self, blocks: Vec<SignedSidechainBlock>) -> WorkerResult<()> {
		match self.worker.get_worker().as_ref() {
			Some(w) => {
				let handle = self.tokio_handle.get_handle();
				handle.block_on(w.gossip_blocks(blocks))
			},
			None => {
				error!("Failed to get worker instance");
				Err(Error::ApplicationSetupError)
			},
		}
	}
}
