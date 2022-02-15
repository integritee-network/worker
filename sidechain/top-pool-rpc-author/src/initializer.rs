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
	api::SidechainApi,
	author::{Author, AuthorTopFilter},
	pool_types::{BPool, EnclaveRpcConnectionRegistry},
};
use itc_direct_rpc_server::rpc_responder::RpcResponder;
use itp_ocall_api::EnclaveMetricsOCallApi;
use itp_sgx_crypto::ShieldingCrypto;
use itp_stf_state_handler::query_shard_state::QueryShardState;
use its_top_pool::pool::Options as PoolOptions;
use std::sync::Arc;

pub type SidechainRpcAuthor<StateHandler, ShieldingCrypto, OCallApi> =
	Author<BPool, AuthorTopFilter, StateHandler, ShieldingCrypto, OCallApi>;

/// Initialize the author components.
///
/// Creates and initializes the global author container from which the
/// RPC author can be accessed. We do this in a centralized manner, to allow
/// easy feature-gating of the entire sidechain/top-pool feature.
pub fn create_top_pool_rpc_author<StateHandler, ShieldingKey, OCallApi>(
	connection_registry: Arc<EnclaveRpcConnectionRegistry>,
	state_handler: Arc<StateHandler>,
	ocall_api: Arc<OCallApi>,
	shielding_crypto: ShieldingKey,
) -> Arc<SidechainRpcAuthor<StateHandler, ShieldingKey, OCallApi>>
where
	StateHandler: QueryShardState,
	ShieldingKey: ShieldingCrypto,
	OCallApi: EnclaveMetricsOCallApi + Send + Sync + 'static,
{
	let rpc_responder = Arc::new(RpcResponder::new(connection_registry));

	let side_chain_api = Arc::new(SidechainApi::<itp_types::Block>::new());
	let top_pool = Arc::new(BPool::create(PoolOptions::default(), side_chain_api, rpc_responder));

	Arc::new(Author::new(top_pool, AuthorTopFilter {}, state_handler, shielding_crypto, ocall_api))
}
