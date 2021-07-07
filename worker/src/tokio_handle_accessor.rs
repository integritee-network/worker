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

use lazy_static::lazy_static;
use std::sync::Mutex;
use tokio::runtime::Handle;

lazy_static! {
    static ref TOKIO_HANDLE: Mutex<Option<tokio::runtime::Handle>> = Default::default();
}

pub trait TokioHandleAccessor {
    fn get_handle(&self) -> Option<tokio::runtime::Handle>;
}

pub struct TokioHandleAccessorImpl;

// these are the static (global) accessors
// reduce their usage where possible and use an instance of TokioHandleAccessorImpl or the trait
impl TokioHandleAccessorImpl {
    pub fn initialize() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        *TOKIO_HANDLE.lock().unwrap() = Some(rt.handle().clone());
    }

    pub fn read_handle() -> Handle {
        TOKIO_HANDLE.lock().unwrap().as_ref().unwrap().clone()
    }
}

impl TokioHandleAccessor for TokioHandleAccessorImpl {
    fn get_handle(&self) -> Handle {
        TokioHandleAccessorImpl::read_handle()
    }
}
