#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(feature = "sgx")]
use sgx_tstd as std;

use std::vec::Vec;

use codec::{Decode, Encode};
use sp_core::H256;

pub type ShardIdentifier = H256;
// Note in the substratee-pallet-registry this is a struct. But for the coded this does not matter.
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug)]
pub struct Request {
    pub shard: ShardIdentifier,
    pub cyphertext: Vec<u8>,
}

pub type SubstrateeConfirmCallFn = ([u8; 2], ShardIdentifier, H256, Vec<u8>);
pub type ShieldFundsFn = ([u8; 2], Vec<u8>, u128, ShardIdentifier);
pub type CallWorkerFn = ([u8; 2], Request);

#[cfg(feature = "std")]
pub mod calls {
    use sp_core::crypto::Pair;
    use sp_runtime::MultiSignature;
    pub use substratee_node_runtime::{
        substratee_registry::{Enclave, ShardIdentifier},
        AccountId,
    };

    pub fn get_worker_info<P: Pair>(
        api: &substrate_api_client::Api<P>,
        index: u64,
    ) -> Option<Enclave<AccountId, Vec<u8>>>
    where
        MultiSignature: From<P::Signature>,
    {
        api.get_storage_map("SubstrateeRegistry", "EnclaveRegistry", index, None)
    }

    pub fn get_worker_for_shard<P: Pair>(
        api: &substrate_api_client::Api<P>,
        shard: &ShardIdentifier,
    ) -> Option<Enclave<AccountId, Vec<u8>>>
    where
        MultiSignature: From<P::Signature>,
    {
        api.get_storage_map("SubstrateeRegistry", "WorkerForShard", shard, None)
            .and_then(|w| get_worker_info(&api, w))
    }

    pub fn get_worker_amount<P: Pair>(api: &substrate_api_client::Api<P>) -> Option<u64>
    where
        MultiSignature: From<P::Signature>,
    {
        api.get_storage_value("SubstrateeRegistry", "EnclaveCount", None)
    }

    pub fn get_first_worker_that_is_not_equal_to_self<P: Pair>(
        api: &substrate_api_client::Api<P>,
        self_account: &AccountId,
    ) -> Option<Enclave<AccountId, Vec<u8>>>
    where
        MultiSignature: From<P::Signature>,
    {
        // the registry starts indexing its map at one
        for n in 1..=api.get_storage_value("SubstrateeRegistry", "EnclaveCount", None)? {
            let worker = get_worker_info(api, n).unwrap();
            if &worker.pubkey != self_account {
                return Some(worker);
            }
        }
        None
    }

    pub fn get_latest_state<P: Pair>(
        api: &substrate_api_client::Api<P>,
        shard: &ShardIdentifier,
    ) -> Option<[u8; 46]>
    where
        MultiSignature: From<P::Signature>,
    {
        api.get_storage_map("SubstrateeRegistry", "LatestIPFSHash", shard, None)
    }
}
