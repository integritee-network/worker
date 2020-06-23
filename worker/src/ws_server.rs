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

use std::str;
use std::thread;

use sgx_types::*;

use codec::{Decode, Encode};
use log::*;
use std::sync::mpsc::Sender as MpscSender;
use substratee_stf::{ShardIdentifier, Getter};
use substratee_worker_api::requests::*;
use ws::{listen, CloseCode, Handler, Message, Result, Sender};

use crate::enclave::api::{enclave_query_state, enclave_shielding_key};

#[derive(Clone, Debug)]
pub struct WsServerRequest {
    client: Sender,
    request: ClientRequest,
}

impl WsServerRequest {
    pub fn new(client: Sender, request: ClientRequest) -> Self {
        Self { client, request }
    }
}

pub fn start_ws_server(addr: String, worker: MpscSender<WsServerRequest>) {
    // Server WebSocket handler
    struct Server {
        client: Sender,
        worker: MpscSender<WsServerRequest>,
    }

    impl Handler for Server {
        fn on_message(&mut self, msg: Message) -> Result<()> {
            info!(
                "[WS Server] Forwarding message to worker event loop: {:?}",
                msg
            );

            match ClientRequest::decode(&mut msg.into_data().as_slice()) {
                Ok(req) => {
                    self.worker
                        .send(WsServerRequest::new(self.client.clone(), req))
                        .unwrap();
                }
                Err(e) => self.client.send("Could not decode request").unwrap()
            }
            Ok(())
        }

        fn on_close(&mut self, code: CloseCode, reason: &str) {
            info!("[WS Server] WebSocket closing for ({:?}) {}", code, reason);
        }
    }
    // Server thread
    info!("Starting WebSocket server on {}", addr);
    thread::spawn(move || {
        listen(addr, |out| Server {
            client: out,
            worker: worker.clone(),
        })
        .unwrap()
    });
}

pub fn handle_request(
    req: WsServerRequest,
    eid: sgx_enclave_id_t,
    mu_ra_port: String,
) -> Result<()> {
    info!("     [WS Server] Got message '{:?}'. ", req);
    let answer = match req.request {
        ClientRequest::PubKeyWorker => get_pubkey(eid),
        ClientRequest::MuRaPortWorker => Message::text(mu_ra_port),
        ClientRequest::StfState(getter, shard) => get_stf_state(eid, getter, shard),
    };

    req.client.send(answer)
}

fn get_stf_state(
    eid: sgx_enclave_id_t,
    getter: Getter,
    shard: ShardIdentifier,
) -> Message {
    info!("     [WS Server] Query state");
    let value = match enclave_query_state(eid, getter.encode(), shard.encode()) {
        Ok(val) => Some(val),
        Err(_) => {
            error!("query state failed");
            None
        }
    };
    // we could strip the whitespace padding here, but actually constant message size is a privacy feature!
    debug!("get_state result: {:?}", value);
    Message::text(hex::encode(value.encode()))
}

fn get_pubkey(eid: sgx_enclave_id_t) -> Message {
    let rsa_pubkey = enclave_shielding_key(eid).unwrap();
    debug!("     [WS Server] RSA pubkey {:?}\n", rsa_pubkey);

    let rsa_pubkey_json = serde_json::to_string(&rsa_pubkey).unwrap();
    Message::text(rsa_pubkey_json)
}
