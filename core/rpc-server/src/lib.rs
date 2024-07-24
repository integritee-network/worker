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

use its_peer_fetch::block_fetch_server::BlockFetchServerModuleBuilder;
use its_primitives::types::block::SignedBlock;
use its_storage::interface::FetchBlocks;
use jsonrpsee::{types::error::CallError, ws_server::WsServerBuilder};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::ToSocketAddrs;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub async fn run_server<FetchSidechainBlocks>(
	addr: impl ToSocketAddrs,
	sidechain_block_fetcher: Arc<FetchSidechainBlocks>,
) -> anyhow::Result<SocketAddr>
where
	FetchSidechainBlocks: FetchBlocks<SignedBlock> + Send + Sync + 'static,
{
	let mut server = WsServerBuilder::default().build(addr).await?;

	let fetch_sidechain_blocks_module = BlockFetchServerModuleBuilder::new(sidechain_block_fetcher)
		.build()
		.map_err(|e| CallError::Failed(e.to_string().into()))?; // `to_string` necessary due to no all errors implementing Send + Sync.
	server.register_module(fetch_sidechain_blocks_module).unwrap();

	let socket_addr = server.local_addr()?;
	tokio::spawn(async move { server.start().await });

	println!("[+] Untrusted RPC server is spawned on: {} listening ", socket_addr);

	Ok(socket_addr)
}
