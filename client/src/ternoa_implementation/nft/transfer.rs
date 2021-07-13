use crate::{get_accountid_from_str, get_pair_from_str};
use codec::Decode;
use log::*;
use my_node_primitives::{AccountId, NFTId};
use sp_application_crypto::sr25519;
use sp_core::{sr25519 as sr25519_core, Pair};
use std::convert::TryFrom;
use std::sync::mpsc::channel;
use substrate_api_client::{
    compose_extrinsic, events::EventsDecoder, Api, GenericAddress, XtStatus,
};

#[derive(Decode)]
struct TransferArgs {
    nft_id: NFTId,
    old_owner: AccountId,
    new_owner: AccountId,
}

///Transfer an NFT from an account to another one.
///Must be called by the current owner of the NFT.
pub fn transfer(from: &str, to: &str, nft_id: NFTId, chain_api: Api<sr25519::Pair>) {
    let signer = get_pair_from_str(from);
    let account_id = get_accountid_from_str(to);
    let chain_api = chain_api.set_signer(sr25519_core::Pair::from(signer));
    let to_id = GenericAddress::Id(account_id);
    info!("transfer the nft {} from {} to {}", nft_id, from, to);

    // compose the extrinsic
    let xt = compose_extrinsic!(chain_api, "Nfts", "transfer", nft_id, to_id);

    let tx_hash = chain_api
        .send_extrinsic(xt.hex_encode(), XtStatus::InBlock)
        .unwrap();
    info!("nft transfer extrinsic sent. Block Hash: {:?}", tx_hash);
    info!("waiting for confirmation of nft transfer");

    //subscribe to event Created
    let (events_in, events_out) = channel();
    chain_api.subscribe_events(events_in).unwrap();

    //Wait for Transfer event
    let mut decoder = EventsDecoder::try_from(chain_api.metadata.clone()).unwrap();
    decoder.register_type_size::<NFTId>("NFTId").unwrap();
    decoder
        .register_type_size::<AccountId>("AccountId")
        .unwrap();
    decoder
        .register_type_size::<AccountId>("AccountId")
        .unwrap();

    let old_account_id = get_accountid_from_str(from);
    debug!("AccountId of signer  {:?}", old_account_id);

    loop {
        let ret = chain_api
            .wait_for_event::<TransferArgs>("Nfts", "Transfer", Some(decoder.clone()), &events_out)
            .unwrap();

        info!("Transfer event received");
        if ret.nft_id == nft_id {
            debug!("NFTId: {:?}", ret.nft_id);
            debug!("old owner accountId: {:?}", ret.old_owner);
            debug!("new owner accountId: {:?}", ret.new_owner);
            break;
        }
    }
}
