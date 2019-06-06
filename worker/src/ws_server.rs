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

extern crate sgx_types;
extern crate ws;

use sgx_types::*;
use ws::{listen, CloseCode, Sender, Handler, Message, Result};
use std::thread;
use enclave_api::get_counter;
use log::*;

pub fn start_ws_server(eid: sgx_enclave_id_t) {
    // Server WebSocket handler
    struct Server {
        out: Sender,
        eid: sgx_enclave_id_t,
    }

    impl Handler for Server {
        fn on_message(&mut self, msg: Message) -> Result<()> {
            info!("[WS Server] Got message '{}'. ", msg);

            let mut retval = sgx_status_t::SGX_SUCCESS;
            let account = msg.clone().into_data();
            let mut value = 0u8;

            let result = unsafe {
                get_counter(self.eid,
                            &mut retval,
                            account.to_vec().as_ptr(),
                            account.len() as u32,
                            &mut value)
            };

            match result {
                sgx_status_t::SGX_SUCCESS => {},
                _ => { error!("[-] ECALL Enclave failed {}!", result.as_str())}
            }

            let answer = Message::text(format!("Counter of {} = {}", msg, value));
            self.out.send(answer)
        }

        fn on_close(&mut self, code: CloseCode, reason: &str) {
            info!("[WS Server] WebSocket closing for ({:?}) {}", code, reason);
        }
    }

    // Server thread
    info!("Starting WebSocket server on port 2019");
    thread::spawn(move || {
        listen("127.0.0.1:2019", |out| {
            Server { out, eid }
        }).unwrap()
    });
}