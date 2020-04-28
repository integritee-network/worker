use base58::ToBase58;
use codec::{Decode, Encode};
use log::*;
pub use my_node_runtime::{
    substratee_registry::{Enclave, ShardIdentifier},
    AccountId,
};
use primitives::crypto::Pair;
use runtime_primitives::MultiSignature;
use substrate_api_client::utils::{hexstr_to_u64, hexstr_to_vec};

pub fn get_worker_info<P: Pair>(
    api: &substrate_api_client::Api<P>,
    index: u64,
) -> Enclave<AccountId, Vec<u8>>
where
    MultiSignature: From<P::Signature>,
{
    info!("[>] Get worker's URL at index {}", index);
    let result_str = api
        .get_storage(
            "substraTEERegistry",
            "EnclaveRegistry",
            Some((index).encode()),
        )
        .unwrap();
    debug!("Storage hex_str: {}", result_str);

    let enc = hexstr_to_enclave(result_str);
    info!("[+]: W{} Pubkey is {:?}", index, &enc.pubkey);
    info!("[+]: W{} URL is {:?}", index, enc.url);
    enc
}

pub fn get_worker_for_shard<P: Pair>(
    api: &substrate_api_client::Api<P>,
    shard: &ShardIdentifier,
) -> Option<u64>
where
    MultiSignature: From<P::Signature>,
{
    let result_str = api
        .get_storage("substraTEERegistry", "WorkerForShard", Some(shard.encode()))
        .unwrap();
    match result_str.as_str() {
        "null" => {
            info!(
                "no worker has ever published a state update for shard {}",
                shard.encode().to_base58()
            );
            None
        }
        _ => Some(hexstr_to_u64(result_str).unwrap()),
    }
}

pub fn get_worker_amount<P: Pair>(api: &substrate_api_client::Api<P>) -> u64
where
    MultiSignature: From<P::Signature>,
{
    let result_str = api
        .get_storage("substraTEERegistry", "EnclaveCount", None)
        .unwrap();
    debug!("get_worker_amount() ret {:?}", result_str);
    let amount = match result_str.as_str() {
        "null" => 0u64,
        _ => hexstr_to_u64(result_str).unwrap(),
    };
    info!("[+]: Amount of Registered Workers {:?}", amount);
    amount
}

pub fn get_latest_state<P: Pair>(api: &substrate_api_client::Api<P>) -> Option<[u8; 46]>
where
    MultiSignature: From<P::Signature>,
{
    let result_str = api
        .get_storage("substraTEERegistry", "LatestIPFSHash", None)
        .unwrap();
    let unhex = hexstr_to_vec(result_str).unwrap();
    info!("State hash vec: {:?}", unhex);
    let mut h: [u8; 46] = [0; 46];

    match unhex.len() {
        1 => {
            info!("No state update happened yet");
            None
        }
        _ => {
            h.clone_from_slice(&unhex);
            Some(h)
        }
    }
}

fn hexstr_to_enclave(hexstr: String) -> Enclave<AccountId, Vec<u8>> {
    let unhex = hexstr_to_vec(hexstr).unwrap();
    Enclave::decode(&mut &unhex[..]).unwrap()
}
