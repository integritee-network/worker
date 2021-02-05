#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(feature = "sgx")]
use sgx_tstd as std;

use std::string::String;
use std::vec::Vec;

use codec::{Decode, Encode};

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub enum TransactionStatus {
	/// Transaction is submitted to the transaction pool.
	Submitted,
	/// Transaction is part of the future queue.
	Future,
	/// Transaction is part of the ready queue.
	Ready,
	/// The transaction has been broadcast to the given peers.
	Broadcast,
	/// Transaction has been included in block with given hash.
	InBlock,
	/// The block this transaction was included in has been retracted.
	Retracted,
	/// Maximum number of finality watchers has been reached,
	/// old watchers are being removed.
	FinalityTimeout,
	/// Transaction has been finalized by a finality-gadget, e.g GRANDPA
	Finalized,
	/// Transaction has been replaced in the pool, by another transaction
	/// that provides the same tags. (e.g. same (sender, nonce)).
	Usurped,
	/// Transaction has been dropped from the pool because of the limit.
	Dropped,
	/// Transaction is no longer valid in the current state.
	Invalid,
	/// Error occured somewhere in the outside process
	Error,
}

#[derive(Encode, Decode)]
pub struct RpcReturnValue {
    pub value: Vec<u8>, // Hash or Error message
    pub do_watch: bool,
    pub status: TransactionStatus,
}

#[cfg(feature = "std")]
#[derive(Encode, Decode, Serialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Vec<u8>,
    pub id: i32,
}

#[cfg(feature = "std")]
#[derive(Encode, Decode, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub result: Vec<u8>,
    pub id: u32,
}