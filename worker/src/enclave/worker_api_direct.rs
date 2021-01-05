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
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;

use sgx_types::*;

use codec::{Decode, Encode};
use log::*;
use std::sync::mpsc::Sender as MpscSender;
use substratee_stf::{Getter, ShardIdentifier};
use ws::{listen, CloseCode, Handler, Message, Result, Sender};
use std::thread;



extern "C" {
    fn call_rpc_methods(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
		request: *const u8,
		request_len: u32,
		response: *mut u8,
		response_len: u32,
    ) -> sgx_status_t;
}

#[derive(Clone, Debug)]
pub struct DirectWsServerRequest {
    client: Sender,
    request: String,
}

impl DirectWsServerRequest {
    pub fn new(client: Sender, request: String) -> Self {
        Self { client, request }
    }
}

pub fn start_worker_api_direct_server(addr: String, worker: MpscSender<DirectWsServerRequest>) {
    // Server WebSocket handler
    struct Server {
        client: Sender,
        worker: MpscSender<DirectWsServerRequest>,
    }

    impl Handler for Server {
        fn on_message(&mut self, msg: Message) -> Result<()> {
            debug!("Forwarding message to worker api direct event loop: {:?}", msg);            
            self.worker.send(DirectWsServerRequest::new(self.client.clone(), msg.to_string()))
                        .unwrap();
            Ok(())
        }

        fn on_close(&mut self, code: CloseCode, reason: &str) {
            debug!("Direct invocation WebSocket closing for ({:?}) {}", code, reason);
        }
    }
    // Server thread
    info!("Starting direct invocation WebSocket server on {}", addr);
    thread::spawn(move || {
        match listen(addr.clone(), |out| Server {
            client: out,
            worker: worker.clone(),
        }) {
            Ok(_) => (),
            Err(e) => {
                error!("error starting worker direct invocation api server on {}: {}", addr, e);
            }
        };
    });
}


pub fn handle_direct_invocation_request(
	req: DirectWsServerRequest,
    eid: sgx_enclave_id_t,
) -> Result<()> {
    info!("Got message '{:?}'. ", req.request);
    // forwarding rpc string directly to enclave
	let mut retval = sgx_status_t::SGX_SUCCESS;
	//let mut response: &[u8] = "not valid".as_bytes();
	let response_len = 8192;
	let mut response: Vec<u8> = vec![0u8; response_len as usize];
	//let response_len: *mut u32 = &mut (response.len() as u32) as *mut u32;

   // let msg: Vec<char> = req.request.chars().collect();
	let msg = req.request.as_bytes().as_ptr();
	let msg_len: u32 = req.request.len() as u32;


    let result = unsafe {
        call_rpc_methods(eid, &mut retval, msg, msg_len, response.as_mut_ptr(), response_len)
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {
			debug!("[RPC-Call] ECALL success!");
        }
        _ => {
			error!("[RPC-call] ECALL Enclave Failed {}!", result.as_str());
        }
	}
	let response_string: String = String::from_utf8(response).expect("Found invalid UTF-8");

	req.client.send(response_string)
	

	//response_string.clone_from_slice(&response.to_vec())
    //let answer_json = serde_json::to_string(&answer).unwrap();
    //Message::text(answer);

   // req.client.send(answer)
}



/*
// Register rpc methods
	// rpc_method(server, method_name, parameters)	
    
    /// Submit hex-encoded extrinsic for inclusion in block.
	/*#[rpc(name = "silly_seven")]
	rpc_method!(rpc_server, author_submitExtrinsic, ext<Bytes>, {
		// TODO: decode with shielding key
     /*   let xt = match Decode::decode(&mut &ext[..]) {
			Ok(xt) => xt,
			Err(err) => return Json::String("Not ok"),
		};*/
		// TODO authentification
		// TODO: state update (in worker)
		let results = "Ok";
		let returnValue = results.toString;

        Ok(Json::String(returnValue))
    });*/

    /// Returns all pending extrinsics, potentially grouped by sender.
   /* rpc_method!(rpc_server, author_pendingExtrinsics  {
        Vec<Bytes> pendingExtrinsics = Ok(self.pool.ready().map(|tx| tx.data().encode().into()).collect());
        Ok(Json::Vec<Bytes>())
        /*fn pending_extrinsics(&self) -> Result<Vec<Bytes>> {
		Ok(self.pool.ready().map(|tx| tx.data().encode().into()).collect())
	}*/
    });*/

    sgx_status_t::SGX_SUCCESS

}
/*
fn submit_extrinsic(&self, ext: Bytes) -> FutureResult<TxHash<P>> {
	let xt = match Decode::decode(&mut &ext[..]) {
		Ok(xt) => xt,
		Err(err) => return Box::new(result(Err(err.into()))),
	};
	let best_block_hash = self.client.info().best_hash;
	Box::new(self.pool
		.submit_one(&generic::BlockId::hash(best_block_hash), TX_SOURCE, xt)
		.compat()
		.map_err(|e| e.into_pool_error()
			.map(Into::into)
			.unwrap_or_else(|e| error::Error::Verification(Box::new(e)).into()))
	)
}*/

/*
/// Substrate authoring RPC API
#[rpc]
pub trait AuthorApi<Hash, BlockHash> {
	/// RPC metadata
	type Metadata;


	/// Submit an extrinsic to watch.
	///
	/// See [`TransactionStatus`](sp_transaction_pool::TransactionStatus) for details on transaction
	/// life cycle.
	#[pubsub(
		subscription = "author_extrinsicUpdate",
		subscribe,
		name = "author_submitAndWatchExtrinsic"
	)]
	fn watch_extrinsic(&self,
		metadata: Self::Metadata,
		subscriber: Subscriber<TransactionStatus<Hash, BlockHash>>,
		bytes: Bytes
    ); 

    /// All new head subscription
	fn subscribe_all_heads(
		&self,
		_metadata: crate::Metadata,
		subscriber: Subscriber<Block::Header>,
	) {
		subscribe_headers(
			self.client(),
			self.subscriptions(),
			subscriber,
			|| self.client().info().best_hash,
			|| self.client().import_notification_stream()
				.map(|notification| Ok::<_, ()>(notification.header))
				.compat(),
		)
	}
}

#[rpc]
	/// All head subscription
	#[pubsub(subscription = "chain_allHead", subscribe, name = "chain_subscribeAllHeads")]
	fn subscribe_all_heads(&self, metadata: Self::Metadata, subscriber: Subscriber<Header>);

	/// Unsubscribe from all head subscription.
	#[pubsub(subscription = "chain_allHead", unsubscribe, name = "chain_unsubscribeAllHeads")]
	fn unsubscribe_all_heads(
		&self,
		metadata: Option<Self::Metadata>,
		id: SubscriptionId,
	) -> RpcResult<bool>;


	/// TODO: custom getter for either public data (permissionless) or private data (authenticated, only over wss://)
	#[rpc(name = "state_get")]
	fn get(&self, name: String, bytes: Bytes, hash: Option<Hash>) -> FutureResult<Bytes>;

	/// Returns the runtime metadata as an opaque blob.
	#[rpc(name = "state_getMetadata")]
	fn metadata(&self, hash: Option<Hash>) -> FutureResult<Bytes>;

	/// Get the runtime version.
	#[rpc(name = "state_getRuntimeVersion", alias("chain_getRuntimeVersion"))]
	fn runtime_version(&self, hash: Option<Hash>) -> FutureResult<RuntimeVersion>;

	/// Get the node's implementation name. Plain old string.
	#[rpc(name = "system_name")]
	fn system_name(&self) -> SystemResult<String>;

	/// Get the node implementation's version. Should be a semver string.
	#[rpc(name = "system_version")]
    fn system_version(&self) -> SystemResult<String>;
    
	/// Return health status of the node.
	///
	/// Node is considered healthy if it is:
	/// - connected to some peers (unless running in dev mode)
	/// - not performing a major sync
	#[rpc(name = "system_health", returns = "Health")]
	fn system_health(&self) -> Receiver<Health>;

}
// RPC Methods: Get all available RPC methods (see ZIM)
curl -H "Content-Type: application/json" -d '{"id":1, "jsonrpc":"2.0", "method": "rpc_methods"}' http://localhost:9933/
*/
*/
