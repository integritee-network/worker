use sp_application_crypto::sr25519;
use sp_core::{sr25519 as sr25519_core, Pair};
use substrate_api_client::{compose_extrinsic, events::EventsDecoder, Api, XtStatus};

use crate::{get_accountid_from_str, get_pair_from_str};
use codec::Decode;
use log::*;
use my_node_primitives::{AccountId, NFTId};
use std::convert::TryFrom;
use std::sync::mpsc::channel;

pub type NFTSeriesId = u32;
pub type NFTIdOf = NFTId;

#[derive(Decode)]
struct CreatedArgs {
    nft_id: NFTId,
    account_id: AccountId,
    series_id: NFTSeriesId,
}

/// Create a NFT for this owner
/// The NFT contains a filename of the capsule/ciphertext file.
/// Returns the NFTid: u32
/// Note: the series id, this nft belongs to, is hardcoded to 0 (the default series id) and the capsule flag is true
pub fn create(owner_ss58: &str, filename: &str, chain_api: Api<sr25519::Pair>) -> Option<NFTId> {
    let signer = get_pair_from_str(owner_ss58);
    let chain_api = chain_api.set_signer(sr25519_core::Pair::from(signer));
    // compose the extrinsic
    let offchain_uri = filename.as_bytes().to_vec();
    let xt = compose_extrinsic!(chain_api, "Nfts", "create", offchain_uri, 0u32, true);
    let tx_hash = chain_api
        .send_extrinsic(xt.hex_encode(), XtStatus::InBlock)
        .unwrap();
    info!("nft create extrinsic sent. Block Hash: {:?}", tx_hash);
    info!("waiting for confirmation of nft create");

    //subscribe to event Created
    let (events_in, events_out) = channel();
    chain_api.subscribe_events(events_in).unwrap();

    //Wait for Created event to extract and return the NFTid
    let mut decoder = EventsDecoder::try_from(chain_api.metadata.clone()).unwrap();
    decoder.register_type_size::<NFTId>("NFTId").unwrap();
    decoder
        .register_type_size::<AccountId>("AccountId")
        .unwrap();
    decoder
        .register_type_size::<NFTSeriesId>("NFTSeriesId")
        .unwrap();

    let account_id = get_accountid_from_str(owner_ss58);
    debug!("AccountId of signer  {:?}", account_id);

    //For now no possibility to catch here the errors coming from chain. infinite loop.
    //See issue https://github.com/scs/substrate-api-client/issues/138#issuecomment-879733584
    loop {
        let ret = chain_api
            .wait_for_event::<CreatedArgs>("Nfts", "Created", Some(decoder.clone()), &events_out)
            .unwrap();

        info!("Created event received");
        debug!("NFTId: {:?}", ret.nft_id);
        debug!("AccountId: {:?}", ret.account_id);
        debug!("NFTSeriesId: {:?}", ret.series_id);
        if ret.account_id == account_id {
            return Some(ret.nft_id);
        }
    }
}
