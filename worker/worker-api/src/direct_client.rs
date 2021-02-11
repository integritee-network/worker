use log::*;
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender as MpscSender;
use std::thread;

use ws::{connect, Handler, Handshake, Message, Result as ClientResult, Sender, CloseCode};

use substratee_worker_primitives::{RpcRequest};

use sgx_crypto_helper::rsa3072::Rsa3072PubKey;

pub struct DirectWsClient {
    pub out: Sender,
    pub request: String,
    pub result: MpscSender<String>,
    pub do_watch: bool,
}

impl Handler for DirectWsClient {
    fn on_open(&mut self, _: Handshake) -> ClientResult<()> {
        debug!("sending request: {:?}", self.request.clone());
        match self.out.send(self.request.clone()) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }        
    }
    fn on_message(&mut self, msg: Message) -> ClientResult<()> {
        info!("got message");
        debug!("{}", msg);
        self.result.send(msg.to_string()).unwrap();
        if !self.do_watch {
            self.out.close(CloseCode::Normal).unwrap();
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct DirectApi {
    url: String,
}

impl DirectApi {
    pub fn new(url: String) -> Self {
        Self { url }
    }

    /// server connection with only one response
    pub fn get(&self, request: String) -> Result<String, ()> {
        let url = self.url.clone();
        let (port_in, port_out) = channel();

        info!("[WorkerApi Direct]: Sending request: {:?}", request);
        let client = thread::spawn(move || {
            match connect(url, |out| DirectWsClient {
                out,
                request: request.clone(),
                result: port_in.clone(),
                do_watch: false,
            }) {
                Ok(c) => c,
                Err(_) => {
                    error!("Could not connect to direct invoation server");
                }
            }
        });
        client.join().unwrap();

        match port_out.recv() {
            Ok(p) => Ok(p),
            Err(_) => {
                error!("[-] [WorkerApi Direct]: error while handling request, returning");
                Err(())
            }
        }
    }
    /// server connection with more than one response
    pub fn watch(&self, request: String, sender: MpscSender<String>) -> Result<(), ()> {
        let url = self.url.clone();

        info!("[WorkerApi Direct]: Sending request: {:?}", request);
        thread::spawn(move || {
            match connect(url, |out| DirectWsClient {
                out,
                request: request.clone(),
                result: sender.clone(),
                do_watch: true,
            }) {
                Ok(c) => c,
                Err(_) => {
                    error!("Could not connect to direct invoation server");
                }
            }
        });
        Ok(())
    }

    pub fn get_rsa_pubkey(&self) -> Result<String, ()> {
        // compose jsonrpc call
        let method =  "author_getShieldingKey".to_owned();
        let jsonrpc_call: String = RpcRequest::compose_jsonrpc_call(method, vec![]);

        let response_str = Self::get(&self, jsonrpc_call)?;       
        
        info!("[+] Got RSA public key of enclave");
        Ok(response_str)
    }
}
