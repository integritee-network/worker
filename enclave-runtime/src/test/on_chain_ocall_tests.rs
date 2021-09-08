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

use crate::ocall::OcallApi;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_types::{WorkerRequest, WorkerResponse};
use log::*;
use std::vec::Vec;
use substrate_api_client::utils::storage_key;

#[allow(unused)]
fn test_ocall_worker_request() {
	info!("testing ocall_worker_request. Hopefully integritee-node is running...");
	let requests =
		vec![WorkerRequest::ChainStorage(storage_key("Balances", "TotalIssuance").0, None)];

	let mut resp: Vec<WorkerResponse<Vec<u8>>> = match OcallApi.worker_request(requests) {
		Ok(response) => response,
		Err(e) => panic!("Worker response decode failed. Error: {:?}", e),
	};

	let first = resp.pop().unwrap();
	info!("Worker response: {:?}", first);

	let (total_issuance, proof) = match first {
		WorkerResponse::ChainStorage(_storage_key, value, proof) => (value, proof),
	};

	info!("Total Issuance is: {:?}", total_issuance);
	info!("Proof: {:?}", proof)
}
