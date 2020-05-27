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

use codec::Encode;
use log::*;
use substratee_stf::ShardIdentifier;
use substratee_worker_api::requests::*;
use ws::{listen, CloseCode, Handler, Message, Result, Sender};

use crate::enclave::api::{enclave_query_state, enclave_shielding_key};

pub fn start_ws_server(eid: sgx_enclave_id_t, addr: String, mu_ra_port: String) {
    // Server WebSocket handler
    struct Server {
        out: Sender,
        eid: sgx_enclave_id_t,
        mu_ra_port: String,
    }

    impl Handler for Server {
        fn on_message(&mut self, msg: Message) -> Result<()> {
            info!("     [WS Server] Got message '{}'. ", msg);

            let msg_txt = msg.into_text().unwrap();
            let args: Vec<&str> = msg_txt.split("::").collect();

            let answer = match args[0] {
                MSG_GET_PUB_KEY_WORKER => get_worker_pub_key(self.eid),
                MSG_GET_MU_RA_PORT => Message::text(self.mu_ra_port.clone()),
                MSG_GET_STF_STATE => handle_get_stf_state_msg(self.eid, args[1], args[2]),
                _ => Message::text("[WS Server]: unrecognized msg pattern"),
            };

            self.out.send(answer)
        }

        fn on_close(&mut self, code: CloseCode, reason: &str) {
            info!("[WS Server] WebSocket closing for ({:?}) {}", code, reason);
        }
    }
    // Server thread
    info!("Starting WebSocket server on {}", addr);
    thread::spawn(move || {
        listen(addr, |out| Server {
            out,
            eid,
            mu_ra_port: mu_ra_port.clone(),
        })
        .unwrap()
    });
}

fn handle_get_stf_state_msg(eid: sgx_enclave_id_t, getter_str: &str, shard_str: &str) -> Message {
    info!("     [WS Server] Query state");
    let getter_vec = hex::decode(getter_str).unwrap();
    let shard = ShardIdentifier::from_slice(&hex::decode(shard_str).unwrap());

    let value = match enclave_query_state(eid, getter_vec, shard.encode()) {
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

fn get_worker_pub_key(eid: sgx_enclave_id_t) -> Message {
    let rsa_pubkey = enclave_shielding_key(eid).unwrap();
    debug!("     [WS Server] RSA pubkey {:?}\n", rsa_pubkey);

    let rsa_pubkey_json = serde_json::to_string(&rsa_pubkey).unwrap();
    Message::text(rsa_pubkey_json)
}
