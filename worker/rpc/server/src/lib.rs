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

use log::debug;

use jsonrpsee::{
    types::error::CallError,
    ws_server::{RpcModule, WsServerBuilder},
};
use tokio::net::ToSocketAddrs;

use substratee_enclave_api::EnclaveApi;

#[cfg(test)]
mod tests;

pub async fn run_server<Enclave>(
    addr: impl ToSocketAddrs,
    enclave: Enclave,
) -> anyhow::Result<SocketAddr>
where
    Enclave: EnclaveApi,
{
    let mut server = WsServerBuilder::default().build(addr).await?;

    let mut module = RpcModule::new(enclave);

    module.register_method("sidechain_importBlock", |params, enclave| {
        debug!("sidechain_importBlock params: {:?}", params);

        enclave
            .rpc(params.one()?)
            .map_err(|e| CallError::Failed(e.into()))

    })?;

    server.register_module(module).unwrap();

    let socket_addr = server.local_addr()?;
    tokio::spawn(async move { server.start().await });
    Ok(socket_addr)
}
