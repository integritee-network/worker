#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

pub mod block;

use codec::{Decode, Encode};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "sgx")]
use sgx_tstd as std;
use sp_core::H256;
use std::vec::Vec;

pub type BlockHash = H256;
pub type BlockNumber = u64;
pub type ShardIdentifier = H256;

use std::string::String;

//use sp_core::ed25519::Signature;

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub enum DirectRequestStatus {
    /// Direct request was successfully executed
    Ok,
    /// Trusted Call Status
    TrustedOperationStatus(TrustedOperationStatus),
    /// Direct request could not be executed
    Error,
}

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
    InSidechainBlock(BlockHash),
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
}

#[derive(Encode, Decode)]
pub struct RpcReturnValue {
    pub value: Vec<u8>,
    pub do_watch: bool,
    pub status: DirectRequestStatus,
    //pub signature: Signature,
}
impl RpcReturnValue {
    pub fn new(val: Vec<u8>, watch: bool, status: DirectRequestStatus) -> Self {
        Self {
            value: val,
            do_watch: watch,
            status,
            //signature: sign,
        }
    }
}

#[derive(Clone, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
// Todo: result should not be Vec<u8>, but `T: Serialize`
pub struct RpcResponse {
    pub jsonrpc: String,
    pub result: Vec<u8>, // encoded RpcReturnValue
    pub id: u32,
}

#[derive(Clone, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
// Todo: params should not be Vec<u8>, but `T: Serialize`
pub struct RpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Vec<u8>,
    pub id: i32,
}

#[cfg(feature = "std")]
impl RpcRequest {
    pub fn compose_jsonrpc_call(method: String, data: Vec<u8>) -> String {
        let direct_invocation_call = RpcRequest {
            jsonrpc: "2.0".to_owned(),
            method,
            params: data,
            id: 1,
        };
        serde_json::to_string(&direct_invocation_call).unwrap()
    }
}
