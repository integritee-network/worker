use log::*;
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender as MpscSender;
use std::thread;

use ws::{connect, Handler, Handshake, Message, Result as ClientResult, Sender};

use crate::requests::ClientRequest;
use crate::client::WsClient;

use sgx_crypto_helper::rsa3072::Rsa3072PubKey;

pub struct DirectWsClient {
    pub out: Sender,
    pub request: String,
    pub result: MpscSender<String>,
    pub watch: bool,
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

    pub fn get(&self, request: ClientRequest) -> Result<String, ()> {
        let url = self.url.clone();
        let (port_in, port_out) = channel();

        info!("[WorkerApi Direct]: Sending request: {:?}", request);
        let client = thread::spawn(move || {
            match connect(url, |out| WsClient {
                out,
                request: request.clone(),
                result: port_in.clone(),
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
    pub fn watch(&self, request: String, sender: MpscSender<String>) -> Result<(), ()> {
        let url = self.url.clone();

        info!("[WorkerApi Direct]: Sending request: {:?}", request);
        thread::spawn(move || {
            match connect(url, |out| DirectWsClient {
                out,
                request: request.clone(),
                result: sender.clone(),
                watch: true,
            }) {
                Ok(c) => c,
                Err(_) => {
                    error!("Could not connect to direct invoation server");
                }
            }
        });
        Ok(())
    }

    pub fn get_rsa_pubkey(&self) -> Result<Rsa3072PubKey, ()> {
        let keystr = Self::get(&self, ClientRequest::PubKeyWorker)?;

        let rsa_pubkey: Rsa3072PubKey = serde_json::from_str(&keystr).unwrap();
        info!("[+] Got RSA public key of enclave");
        debug!("  enclave RSA pubkey = {:?}", rsa_pubkey);
        Ok(rsa_pubkey)
    }
}
