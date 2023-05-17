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

use crate::{
	parentchain_handler::{HandleParentchain, ParentchainHandler},
	tests::mocks::{enclave_api_mock::EnclaveMock, parentchain_api_mock::ParentchainApiMock},
};
use itc_parentchain::{
	light_client::light_client_init_params::SimpleParams, primitives::ParentchainInitParams,
};
use itc_parentchain_test::ParentchainHeaderBuilder;
use itp_node_api::api_client::ChainApi;
use std::sync::Arc;

#[test]
fn test_number_of_synced_blocks() {
	let number_of_blocks = 42;

	let parentchain_api_mock = ParentchainApiMock::new().with_default_blocks(number_of_blocks);
	let last_synced_block =
		parentchain_api_mock.get_blocks(2, 2).unwrap().first().cloned().unwrap();

	let enclave_api_mock = EnclaveMock;
	let parentchain_params: ParentchainInitParams =
		SimpleParams { genesis_header: ParentchainHeaderBuilder::default().build() }.into();

	let parentchain_handler = ParentchainHandler::new(
		parentchain_api_mock,
		Arc::new(enclave_api_mock),
		parentchain_params,
	);

	let header = parentchain_handler.sync_parentchain(last_synced_block.block.header).unwrap();
	assert_eq!(header.number, number_of_blocks);
}
