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
use sp_core::sr25519;
use std::sync::Mutex;
use substrate_api_client::Api;

lazy_static! {
    // todo: replace with &str, but use &str in api-client first
    static ref NODE_URL: Mutex<String> = Mutex::new("".to_string());
}

pub trait NodeApiFactory {
    fn create_api(&self) -> Api<sr25519::Pair>;
}

pub struct NodeApiFactoryImpl;

impl NodeApiFactoryImpl {
    pub fn write_node_url(url: String) {
        *NODE_URL.lock().unwrap() = url;
    }

    pub fn read_node_url() -> String {
        NODE_URL.lock().unwrap().clone()
    }

    /// creates a new instance and initializes the global state
    pub fn new(url: String) -> Self {
        NodeApiFactoryImpl::write_node_url(url);

        NodeApiFactoryImpl
    }
}

impl NodeApiFactory for NodeApiFactoryImpl {
    fn create_api(&self) -> Api<sr25519::Pair> {
        Api::<sr25519::Pair>::new(NodeApiFactoryImpl::read_node_url()).unwrap()
    }
}
