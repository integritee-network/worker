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

use std::net::{SocketAddr};

use log::debug;

use jsonrpsee::ws_server::{WsServer};
use tokio::net::ToSocketAddrs;

#[cfg(test)]
mod tests;

pub async fn run_server(addr: impl ToSocketAddrs) -> anyhow::Result<SocketAddr> {
	let mut server = WsServer::new(addr).await?;

	server.register_method("author_importBlock", |params| {
		debug!("author_importBlock params: {:?}", params);
		Ok("Hello")
	})?;

	server.register_method("enclave_directRequest", |params| {
		debug!("enclave_directRequest params: {:?}", params);
		Ok("Hello")
	})?;

	let socket_addr = server.local_addr()?;
	tokio::spawn(async move { server.start().await });
	Ok(socket_addr)
}