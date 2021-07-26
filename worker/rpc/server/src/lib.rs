/*
	Copyright 2019 Supercomputing Systems AG

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

use std::net::SocketAddr;

use jsonrpsee::{
	types::error::CallError,
	ws_server::{RpcModule, WsServerBuilder},
};
use log::debug;
use parity_scale_codec::Encode;
use tokio::net::ToSocketAddrs;

use std::sync::Arc;
use substratee_enclave_api::direct_request::DirectRequest;
use substratee_worker_primitives::{block::SignedBlock, RpcRequest};

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub async fn run_server<Enclave>(
	addr: impl ToSocketAddrs,
	enclave: Arc<Enclave>,
) -> anyhow::Result<SocketAddr>
where
	Enclave: DirectRequest,
{
	let mut server = WsServerBuilder::default().build(addr).await?;

	let mut module = RpcModule::new(enclave);

	module.register_method("sidechain_importBlock", |params, enclave| {
		debug!("sidechain_importBlock params: {:?}", params);

		let enclave_req = RpcRequest::compose_jsonrpc_call(
			"sidechain_importBlock".into(),
			params.one::<Vec<SignedBlock>>()?.encode(),
		);

		enclave
			.rpc(enclave_req.as_bytes().to_vec())
			.map_err(|e| CallError::Failed(e.into()))
	})?;

	server.register_module(module).unwrap();

	let socket_addr = server.local_addr()?;
	tokio::spawn(async move { server.start().await });
	Ok(socket_addr)
}
