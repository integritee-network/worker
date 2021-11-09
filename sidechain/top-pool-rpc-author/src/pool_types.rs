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

use crate::api::SidechainApi;
use itc_direct_rpc_server::{
	rpc_connection_registry::ConnectionRegistry, rpc_responder::RpcResponder,
};
use itc_tls_websocket_server::connection::TungsteniteWsConnection;
use itp_types::Block;
use its_top_pool::basic_pool::BasicPool;

type Hash = sp_core::H256;

pub(crate) type EnclaveRpcConnectionRegistry = ConnectionRegistry<Hash, TungsteniteWsConnection>;

pub type EnclaveRpcResponder =
	RpcResponder<EnclaveRpcConnectionRegistry, Hash, TungsteniteWsConnection>;

pub type BPool = BasicPool<SidechainApi<Block>, Block, EnclaveRpcResponder>;
