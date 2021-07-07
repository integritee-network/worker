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

use crate::config::Config;
use crate::worker::Worker as WorkerGen;
use lazy_static::lazy_static;
use parking_lot::{RwLock, RwLockReadGuard};
use sp_core::sr25519;
use substrate_api_client::Api;
use substratee_enclave_api::Enclave;
use substratee_worker_api::direct_client::DirectClient;

pub type Worker = WorkerGen<Config, Api<sr25519::Pair>, Enclave, DirectClient>;

lazy_static! {
    static ref WORKER: RwLock<Option<Worker>> = RwLock::new(None);
}

pub trait WorkerAccessor {
    fn get_worker<'a>(&self) -> RwLockReadGuard<'a, Option<Worker>>;
}

pub struct WorkerAccessorImpl;

// these are the static (global) accessors
// reduce their usage where possible and use an instance of WorkerAccessorImpl or the trait
impl WorkerAccessorImpl {
    pub fn reset_worker(worker: Worker) {
        *WORKER.write() = Some(worker);
    }

    pub fn read_worker<'a>() -> RwLockReadGuard<'a, Option<Worker>> {
        WORKER.read()
    }
}

impl WorkerAccessor for WorkerAccessorImpl {
    fn get_worker<'a>(&self) -> RwLockReadGuard<'a, Option<Worker>> {
        WorkerAccessorImpl::read_worker()
    }
}
