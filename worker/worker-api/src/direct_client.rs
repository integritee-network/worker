use log::*;
use std::sync::mpsc::Sender as MpscSender;
use ws::{listen, connect, CloseCode, Handler, Message, Result as ClientResult, Sender,  Handshake};
use std::thread;
use std::sync::mpsc::channel;
use codec::Encode;

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
        self.out.close(CloseCode::Normal).unwrap();
        if !self.watch {
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

    pub fn send(&self, request: String) -> Result<String, ()> {
        let url = self.url.clone();
        let (port_in, port_out) = channel();

        info!("[WorkerApi Direct]: Sending request: {:?}", request);
        let client = thread::spawn(move || {
            match connect(url, |out| DirectWsClient {
                out,
                request: request.clone(),
                result: port_in.clone(),
                watch: false,
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
        //let (port_in, port_out) = channel();

        info!("[WorkerApi Direct]: Sending request: {:?}", request);
        let client = thread::spawn(move || {
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
        client.join().unwrap();
        Ok(()) 
    }
    
}