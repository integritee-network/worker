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
	api::SideChainApi,
	author::{Author, AuthorTopFilter},
	global_author_container::GlobalAuthorContainer,
	pool_types::{BPool, EnclaveRpcConnectionRegistry},
};
use itc_direct_rpc_server::rpc_responder::RpcResponder;
use itp_stf_state_handler::GlobalFileStateHandler;
use its_top_pool::pool::Options as PoolOptions;
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;
use std::sync::Arc;

/// Initialize the author components.
///
/// Creates and initializes the global author container from which the
/// RPC author can be accessed. We do this in a centralized manner, to allow
/// easy feature-gating of the entire sidechain/top-pool feature.
pub fn initialize_top_pool_rpc_author(
	connection_registry: Arc<EnclaveRpcConnectionRegistry>,
	shielding_key: Rsa3072KeyPair,
) {
	let rpc_responder = Arc::new(RpcResponder::new(connection_registry));

	let side_chain_api = Arc::new(SideChainApi::<itp_types::Block>::new());
	let top_pool = Arc::new(BPool::create(PoolOptions::default(), side_chain_api, rpc_responder));
	let state_handler = Arc::new(GlobalFileStateHandler);

	let rpc_author =
		Arc::new(Author::new(top_pool, AuthorTopFilter {}, state_handler, shielding_key));

	GlobalAuthorContainer::initialize(rpc_author.clone());
}
