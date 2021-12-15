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

use itp_enclave_api::direct_request::DirectRequest;
use itp_types::RpcRequest;
use its_primitives::types::{
	BlockHash, ShardIdentifier, SignedBlock, SignedBlock as SignedSidechainBlock,
};
use its_storage::interface::FetchBlocks;
use jsonrpsee::{
	types::error::CallError,
	ws_server::{RpcModule, WsServerBuilder},
};
use log::debug;
use parity_scale_codec::Encode;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::ToSocketAddrs;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub async fn run_server<Enclave, FetchSidechainBlocks>(
	addr: impl ToSocketAddrs,
	enclave: Arc<Enclave>,
	sidechain_block_fetcher: Arc<FetchSidechainBlocks>,
) -> anyhow::Result<SocketAddr>
where
	Enclave: DirectRequest,
	FetchSidechainBlocks: FetchBlocks<SignedSidechainBlock> + Send + Sync + 'static,
{
	let mut server = WsServerBuilder::default().build(addr).await?;

	let mut import_sidechain_block_module = RpcModule::new(enclave);
	import_sidechain_block_module.register_method("sidechain_importBlock", |params, enclave| {
		debug!("sidechain_importBlock params: {:?}", params);

		let enclave_req = RpcRequest::compose_jsonrpc_call(
			"sidechain_importBlock".into(),
			params.one::<Vec<SignedBlock>>()?.encode(),
		);

		enclave
			.rpc(enclave_req.as_bytes().to_vec())
			.map_err(|e| CallError::Failed(e.into()))
	})?;
	server.register_module(import_sidechain_block_module).unwrap();

	let mut fetch_sidechain_blocks_module = RpcModule::new(sidechain_block_fetcher);
	fetch_sidechain_blocks_module.register_method(
		"sidechain_fetchBlocksFromPeer",
		|params, sidechain_block_fetcher| {
			debug!("sidechain_fetchBlocksFromPeer: {:?}", params);
			let (block_hash, shard_identifier) = params.one::<(BlockHash, ShardIdentifier)>()?;
			sidechain_block_fetcher
				.fetch_all_blocks_following(&block_hash, &shard_identifier)
				.map_err(|e| CallError::Failed(e.into()))
		},
	)?;
	server.register_module(fetch_sidechain_blocks_module).unwrap();

	let socket_addr = server.local_addr()?;
	tokio::spawn(async move { server.start().await });
	Ok(socket_addr)
}
