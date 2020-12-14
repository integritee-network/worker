//#[macro_use(rpc_method)]
//#[cfg(feature = "std")]
//extern crate json_rpc;
//use json_rpc::{Server, Json, Error};


use std::backtrace::{self, PrintFormat};
//use std::io::{Read, Write};
//use std::net::TcpStream;
use std::sync::Arc;
use std::vec::Vec;

//use sgx_types::*;

use log::*;
use rustls::{ClientConfig, ClientSession, ServerConfig, ServerSession, Stream};

use crate::aes;
use crate::attestation::{create_ra_report_and_signature, DEV_HOSTNAME};
use crate::cert;
use crate::rsa3072;
use crate::utils::UnwrapOrSgxErrorUnexpected;

use substrate_api_client::{utils::hexstr_to_vec, Api, XtStatus};
use substratee_node_runtime::{
    substratee_registry::ShardIdentifier, Event, Hash, Header, SignedBlock, UncheckedExtrinsic,
};

#[rpc]
pub trait AuthorRpc {
    #[rpc(name = "author_submitExtrinsic")]
    fn silly_7(&self) -> Result<u64>;
}

pub struct Author;

impl AuthorRpc for Author {
    fn silly_7(&self) -> Result<u64> {
        Ok(7)
    }


}

#[no_mangle]
pub unsafe extern "C" fn start_worker_api_direct(
    socket_fd: c_int,
	sign_type: sgx_quote_sign_type_t,
) -> sgx_status_t {
	let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);

	let mut rpc_server = Server::new();

	mod author_rpc;

	let mut io = jsonrpc_core::IoHandler::default();

    // Add a silly RPC that returns constant values
    io.extend_with(crate::author_rpc::AuthorRpc::to_delegate(
        crate::author_rpc::Author {},
    ));


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