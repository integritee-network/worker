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
