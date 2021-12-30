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

use crate::{
	error::Error,
	globals::worker::GetMutWorker,
	worker::{UpdatePeers, WorkerResult},
};
use log::*;
use std::sync::Arc;

#[cfg(test)]
use mockall::predicate::*;
#[cfg(test)]
use mockall::*;

/// Updates the peers of the global worker.
#[cfg_attr(test, automock)]
pub trait UpdateWorkerPeers {
	fn update_peers(&self) -> WorkerResult<()>;
}

pub struct GlobalPeerUpdater<Worker> {
	worker: Arc<Worker>,
}

impl<Worker> GlobalPeerUpdater<Worker> {
	pub fn new(worker: Arc<Worker>) -> Self {
		GlobalPeerUpdater { worker }
	}
}

// FIXME: We should write unit tests for this one here - but with the global worker struct, which is not yet made to be mocked,
// this would require a lot of changes.
impl<Worker> UpdateWorkerPeers for GlobalPeerUpdater<Worker>
where
	Worker: GetMutWorker,
{
	fn update_peers(&self) -> WorkerResult<()> {
		let maybe_worker = &mut *self.worker.get_mut_worker();
		match maybe_worker {
			Some(w) => w.update_peers(),
			None => {
				error!("Failed to get worker instance");
				Err(Error::ApplicationSetup)
			},
		}
	}
}
