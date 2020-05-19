#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(feature = "sgx")]
use sgx_tstd as std;

use std::vec::Vec;

use sp_core::H256;

pub type ShardIdentifier = H256;
// Note in the substratee-pallet-registry this is a struct. But for the coded this does not matter.
pub type Request = (ShardIdentifier, Vec<u8>);

pub type SubstrateeConfirmCallFn = ([u8; 2], ShardIdentifier, Vec<u8>, Vec<u8>);
pub type ShieldFundsFn = ([u8; 2], Vec<u8>, u128, ShardIdentifier);
pub type CallWorkerFn = ([u8; 2], Request);

#[cfg(feature = "std")]
pub mod calls {
    pub use my_node_runtime::{
        substratee_registry::{Enclave, ShardIdentifier},
        AccountId,
    };
    use sp_core::crypto::Pair;
    use sp_runtime::MultiSignature;

    pub fn get_worker_info<P: Pair>(
        api: &substrate_api_client::Api<P>,
        index: u64,
    ) -> Option<Enclave<AccountId, Vec<u8>>>
    where
        MultiSignature: From<P::Signature>,
    {
        api.get_storage_map("SubstrateeRegistry", "EnclaveRegistry", index)
    }

    pub fn get_worker_for_shard<P: Pair>(
        api: &substrate_api_client::Api<P>,
        shard: &ShardIdentifier,
    ) -> Option<u64>
    where
        MultiSignature: From<P::Signature>,
    {
        api.get_storage_map("SubstrateeRegistry", "WorkerForShard", shard)
    }

    pub fn get_worker_amount<P: Pair>(api: &substrate_api_client::Api<P>) -> Option<u64>
    where
        MultiSignature: From<P::Signature>,
    {
        api.get_storage_value("SubstrateeRegistry", "EnclaveCount")
    }

    pub fn get_latest_state<P: Pair>(
        api: &substrate_api_client::Api<P>,
        shard: &ShardIdentifier,
    ) -> Option<[u8; 46]>
    where
        MultiSignature: From<P::Signature>,
    {
        api.get_storage_map("SubstrateeRegistry", "LatestIPFSHash", shard)
    }
}
