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

#[cfg(test)]
use mockall::predicate::*;
#[cfg(test)]
use mockall::*;

use crate::worker::{UpdatePeers, WorkerResult};
use itp_types::ShardIdentifier;
use std::sync::Arc;

/// Updates the peers of the global worker.
#[cfg_attr(test, automock)]
pub trait UpdateWorkerPeers {
	fn update_peers(&self, shard: ShardIdentifier) -> WorkerResult<u32>;
}

pub struct WorkerPeersUpdater<WorkerType> {
	worker: Arc<WorkerType>,
}

impl<WorkerType> WorkerPeersUpdater<WorkerType> {
	pub fn new(worker: Arc<WorkerType>) -> Self {
		WorkerPeersUpdater { worker }
	}
}

impl<WorkerType> UpdateWorkerPeers for WorkerPeersUpdater<WorkerType>
where
	WorkerType: UpdatePeers,
{
	fn update_peers(&self, shard: ShardIdentifier) -> WorkerResult<u32> {
		self.worker.update_peers(shard)
	}
}
