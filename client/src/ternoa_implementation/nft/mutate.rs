use crate::get_pair_from_str;
use codec::Decode;
use log::*;
use my_node_primitives::NFTId;
use sp_application_crypto::sr25519;
use sp_core::{sr25519 as sr25519_core, Pair};
use std::convert::TryFrom;
use std::sync::mpsc::channel;
use substrate_api_client::{compose_extrinsic, events::EventsDecoder, Api, XtStatus};

#[derive(Decode)]
struct MutatedArgs {
    nft_id: NFTId,
}

/// Update the file included in the NFT with id nft_id.
/// Must be called by the owner of the NFT and while the NFT is not sealed.
/// Note: the series id, this nft belongs to, is hardcoded to 1 and the capsule flag is true.
pub fn mutate(owner_ss58: &str, nft_id: u32, new_filename: &str, chain_api: Api<sr25519::Pair>) {
    let signer = get_pair_from_str(owner_ss58);
    let chain_api = chain_api.set_signer(sr25519_core::Pair::from(signer));
    // compose the extrinsic
    let offchain_uri = new_filename.as_bytes().to_vec();
    let xt = compose_extrinsic!(
        chain_api,
        "Nfts",
        "mutate",
        nft_id,
        offchain_uri,
        1u32,
        true
    );
    let tx_hash = chain_api
        .send_extrinsic(xt.hex_encode(), XtStatus::InBlock)
        .unwrap();
    info!("nft mutate extrinsic sent. Block Hash: {:?}", tx_hash);
    info!("waiting for confirmation of nft mutate");

    //subscribe to event Mutated
    let (events_in, events_out) = channel();
    chain_api.subscribe_events(events_in).unwrap();

    //Wait for Created event to extract and return the NFTid
    let mut decoder = EventsDecoder::try_from(chain_api.metadata.clone()).unwrap();
    decoder.register_type_size::<NFTId>("NFTId").unwrap();

    loop {
        let ret = chain_api
            .wait_for_event::<MutatedArgs>("Nfts", "Mutated", Some(decoder.clone()), &events_out)
            .unwrap();

        info!("Mutated event received");
        debug!("NFTId: {:?}", ret.nft_id);

        if nft_id == ret.nft_id {
            break;
        }
    }
}
