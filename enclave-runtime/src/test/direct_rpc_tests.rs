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

use crate::{rpc::worker_api_direct::public_api_rpc_handler, Hash};
use codec::{Decode, Encode};
use ita_stf::{Getter, TrustedGetter, TrustedGetterSigned};
use itc_direct_rpc_server::{
	create_determine_watch, rpc_connection_registry::ConnectionRegistry,
	rpc_ws_handler::RpcWsHandler,
};
use itc_tls_websocket_server::{ConnectionToken, WebSocketMessageHandler};
use itp_rpc::{RpcRequest, RpcReturnValue};
use itp_sgx_crypto::get_rsa3072_repository;
use itp_sgx_temp_dir::TempDir;
use itp_stf_executor::{getter_executor::GetterExecutor, mocks::GetStateMock};
use itp_stf_state_observer::mock::ObserveStateMock;
use itp_top_pool_author::mocks::AuthorApiMock;
use itp_types::{AccountId, DirectRequestStatus, Request, ShardIdentifier};
use itp_utils::{FromHexPrefixed, ToHexPrefixed};
use sp_core::ed25519::Signature;
use sp_runtime::MultiSignature;
use std::{string::ToString, sync::Arc, vec::Vec};

pub fn get_state_request_works() {
	type TestState = u64;

	let temp_dir = TempDir::with_prefix("get_state_request_works").unwrap();

	let connection_registry = Arc::new(ConnectionRegistry::<Hash, ConnectionToken>::new());
	let watch_extractor = Arc::new(create_determine_watch::<Hash>());
	let rsa_repository = get_rsa3072_repository(temp_dir.path().to_path_buf()).unwrap();

	let state: TestState = 78234u64;
	let state_observer = Arc::new(ObserveStateMock::<TestState>::new(state));
	let getter_executor =
		Arc::new(GetterExecutor::<_, GetStateMock<TestState>>::new(state_observer));
	let top_pool_author = Arc::new(AuthorApiMock::default());

	let io_handler =
		public_api_rpc_handler(top_pool_author, getter_executor, Arc::new(rsa_repository));
	let rpc_handler = Arc::new(RpcWsHandler::new(io_handler, watch_extractor, connection_registry));

	let getter = Getter::trusted(TrustedGetterSigned::new(
		TrustedGetter::nonce(AccountId::new([0u8; 32])),
		MultiSignature::Ed25519(Signature::from_raw([0u8; 64])),
	));

	let request = Request { shard: ShardIdentifier::default(), cyphertext: getter.encode() };

	let request_string =
		RpcRequest::compose_jsonrpc_call("state_executeGetter".to_string(), vec![request.to_hex()])
			.unwrap();

	let response_string =
		rpc_handler.handle_message(ConnectionToken(1), request_string).unwrap().unwrap();

	assert!(!response_string.is_empty());

	// Because we cannot de-serialize the RpcResponse here (unresolved serde_json and std/sgx feature issue),
	// we hard-code the expected response.
	//error!("{}", response_string);
	//let response: RpcResponse = serde_json::from_str(&response_string).unwrap();

	const EXPECTED_HEX_RETURN_VALUE: &str = "0x2801209a310100000000000000";
	assert!(response_string.contains(EXPECTED_HEX_RETURN_VALUE));
	let rpc_return_value = RpcReturnValue::from_hex(EXPECTED_HEX_RETURN_VALUE).unwrap();
	assert_eq!(rpc_return_value.status, DirectRequestStatus::Ok);
	let decoded_value: Option<Vec<u8>> =
		Option::decode(&mut rpc_return_value.value.as_slice()).unwrap();
	assert_eq!(decoded_value, Some(state.encode()));
}
