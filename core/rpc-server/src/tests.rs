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

use super::*;
use crate::mock::MockSidechainBlockFetcher;

use its_primitives::types::{header::ShardIdentifier, BlockHash};
use its_rpc_handler::constants::RPC_METHOD_NAME_FETCH_BLOCKS_FROM_PEER;
use its_test::sidechain_block_builder::{SidechainBlockBuilderTrait};
use jsonrpsee::{
	types::{to_json_value, traits::Client},
	ws_client::WsClientBuilder,
};
use log::info;



fn init() {
	let _ = env_logger::builder().is_test(true).try_init();
}

#[tokio::test]
async fn test_client_calls() {
	init();
	let addr = run_server("127.0.0.1:0", Arc::new(MockSidechainBlockFetcher)).await.unwrap();
	info!("ServerAddress: {:?}", addr);

	let url = format!("ws://{}", addr);
	let client = WsClientBuilder::default().build(&url).await.unwrap();
	let param_json =
		to_json_value((BlockHash::default(), Option::<()>::None, ShardIdentifier::default()))
			.unwrap();
	let response: Vec<u8> = client
		.request(RPC_METHOD_NAME_FETCH_BLOCKS_FROM_PEER, vec![param_json].into())
		.await
		.unwrap();

	//received no blocks from server
	assert!(response.is_empty());
}
