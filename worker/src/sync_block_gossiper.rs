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

use crate::error::Error;
use crate::tokio_handle_accessor::TokioHandleAccessor;
use crate::worker::{WorkerResult, WorkerT};
use crate::worker_accessor::WorkerAccessor;
use log::*;
use std::sync::Arc;
use substratee_worker_primitives::block::SignedBlock as SignedSidechainBlock;

pub trait SyncBlockGossiper {
    fn gossip_blocks(&self, blocks: Vec<SignedSidechainBlock>) -> WorkerResult<()>;
}

pub struct SyncBlockGossiperImpl<T, W>
where
    T: TokioHandleAccessor,
    W: WorkerAccessor,
{
    tokio_handle_accessor: Arc<T>,
    worker_accessor: Arc<W>,
}

impl<T, W> SyncBlockGossiperImpl<T, W>
where
    T: TokioHandleAccessor,
    W: WorkerAccessor,
{
    pub fn new(tokio_handle_accessor: Arc<T>, worker_accessor: Arc<W>) -> Self {
        SyncBlockGossiperImpl {
            tokio_handle_accessor,
            worker_accessor,
        }
    }
}

impl<T, W> SyncBlockGossiper for SyncBlockGossiperImpl<T, W>
where
    T: TokioHandleAccessor,
    W: WorkerAccessor,
{
    fn gossip_blocks(&self, blocks: Vec<SignedSidechainBlock>) -> WorkerResult<()> {
        match self.worker_accessor.get_worker().as_ref() {
            Some(w) => {
                let handle = self.tokio_handle_accessor.get_handle();
                handle.block_on(w.gossip_blocks(blocks))
            }
            None => {
                error!("Failed to get worker instance");
                return Err(Error::ApplicationSetupError);
            }
        }
    }
}
