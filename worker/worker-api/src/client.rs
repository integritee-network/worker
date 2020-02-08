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

use std::sync::mpsc::Sender as ThreadOut;

use log::*;
use ws::{CloseCode, Handler, Handshake, Message, Result, Sender};

pub struct WsClient {
    pub out: Sender,
    pub request: String,
    pub result: ThreadOut<String>,
}

impl Handler for WsClient {
    fn on_open(&mut self, _: Handshake) -> Result<()> {
        info!("sending request: {}", self.request);

        match self.out.send(self.request.clone()) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
    fn on_message(&mut self, msg: Message) -> Result<()> {
        info!("got message");
        debug!("{}", msg);
        let retstr = msg.as_text().unwrap();

        self.result.send(retstr.to_string()).unwrap();
        self.out.close(CloseCode::Normal).unwrap();
        Ok(())
    }
}
