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

use std::sync::mpsc::channel;
use std::thread;

use sgx_crypto_helper::rsa3072::Rsa3072PubKey;

use codec::{Decode, Encode};
use log::*;
use ws::connect;

use client::WsClient;
use requests::*;
use substratee_stf::{ShardIdentifier, TrustedGetterSigned};

pub mod client;
pub mod requests;

#[derive(Clone)]
pub struct Api {
    url: String,
}

impl Api {
    pub fn new(url: String) -> Api {
        Api {
            url,
        }
    }

    pub fn get_mu_ra_port(&self) -> Result<String, ()> {
        Self::get(&self, MSG_GET_MU_RA_PORT)
    }

    pub fn get_rsa_pubkey(&self) -> Result<Rsa3072PubKey, ()> {
        let keystr = Self::get(&self, MSG_GET_PUB_KEY_WORKER)?;

        let rsa_pubkey: Rsa3072PubKey = serde_json::from_str(&keystr).unwrap();
        info!("[+] Got RSA public key of enclave");
        debug!("  enclave RSA pubkey = {:?}", rsa_pubkey);
        Ok(rsa_pubkey)
    }

    pub fn get_stf_state(
        &self,
        getter: TrustedGetterSigned,
        shard: &ShardIdentifier,
    ) -> Result<Vec<u8>, ()> {
        let getter_str = hex::encode(getter.encode());
        let shard_str = hex::encode(shard.encode());
        let request = format!("{}::{}::{}", MSG_GET_STF_STATE, getter_str, shard_str);
        match Self::get(&self, &request) {
            Ok(res) => {
                let value_slice = hex::decode(&res).unwrap();
                let value: Option<Vec<u8>> = Decode::decode(&mut &value_slice[..]).unwrap();
                match value {
                    Some(val) => Ok(val), // val is still an encoded option! can be None.encode() if storage doesn't exist
                    None => Err(()),      // there must've been an SgxResult::Err inside enclave
                }
            }
            Err(_) => Err(()), // ws error
        }
    }

    fn get(&self, request: &str) -> Result<String, ()> {
        let url = self.url.clone();
        let req = request.to_string();
        let (port_in, port_out) = channel();

        info!("[Worker Api]: Sending request: {}", req);
        let client = thread::spawn(move || {
            match connect(url, |out| WsClient {
                out,
                request: req.clone(),
                result: port_in.clone(),
            }) {
                Ok(c) => c,
                Err(_) => {
                    error!("Could not connect to worker");
                }
            }
        });
        client.join().unwrap();

        match port_out.recv() {
            Ok(p) => Ok(p),
            Err(_) => {
                error!("[-] [WorkerApi]: error while handling request, returning");
                Err(())
            }
        }
    }
}
