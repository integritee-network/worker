#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

use codec::{Decode, Encode};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "sgx")]
use sgx_tstd as std;
use std::vec::Vec;

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub enum TrustedOperationStatus {
    /// TrustedOperation is submitted to the top pool.
    Submitted,
    /// TrustedOperation is part of the future queue.
    Future,
    /// TrustedOperation is part of the ready queue.
    Ready,
    /// The operation has been broadcast to the given peers.
    Broadcast,
    /// TrustedOperation has been included in block with given hash.
    InBlock,
    /// The block this operation was included in has been retracted.
    Retracted,
    /// Maximum number of finality watchers has been reached,
    /// old watchers are being removed.
    FinalityTimeout,
    /// TrustedOperation has been finalized by a finality-gadget, e.g GRANDPA
    Finalized,
    /// TrustedOperation has been replaced in the pool, by another operation
    /// that provides the same tags. (e.g. same (sender, nonce)).
    Usurped,
    /// TrustedOperation has been dropped from the pool because of the limit.
    Dropped,
    /// TrustedOperation is no longer valid in the current state.
    Invalid,
    /// Error occured somewhere outside of the pool
    Error,
}

#[derive(Encode, Decode)]
pub struct RpcReturnValue {
    pub value: Vec<u8>, // Hash or Error message
    pub do_watch: bool,
    pub status: TrustedOperationStatus,
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
