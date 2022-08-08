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

//! Foreign Function interface for all the OCalls.
//! Implementations of C-API functions, that can be called from the Enclave.
//! These should just be wrappers that transform the C-API structures and call the
//! actual implementation of the OCalls (using the traits defined in the bridge_api).

pub mod fetch_sidechain_blocks_from_peer;
pub mod get_ias_socket;
pub mod get_quote;
pub mod get_qve_report_on_quote;
pub mod get_update_info;
pub mod init_quote;
pub mod ipfs;
pub mod propose_sidechain_blocks;
pub mod send_to_parentchain;
pub mod store_sidechain_blocks;
pub mod update_metric;
pub mod worker_request;
