/*
    Copyright 2019 Supercomputing Systems AG

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

*/
use std::fs::{self, File};
use std::io::stdin;
use std::io::Write;
use std::path::Path;
use std::slice;
use std::str;
use std::sync::{
    mpsc::{channel, Sender},
    Mutex,
};
use std::thread;

use sgx_types::*;

use base58::{FromBase58, ToBase58};
use clap::{load_yaml, App};
use codec::{Decode, Encode};
use lazy_static::lazy_static;
use log::*;
use sp_core::{
    crypto::{AccountId32, Ss58Codec},
    sr25519,
    storage::StorageKey,
    Pair,
};
use sp_keyring::AccountKeyring;
use substrate_api_client::{utils::hexstr_to_vec, Api, XtStatus};
use substratee_node_runtime::{
    substratee_registry::ShardIdentifier, Event, Hash, Header, SignedBlock, UncheckedExtrinsic,
};

use crate::enclave::api::{enclave_init_chain_relay, enclave_sync_chain_relay};
use enclave::api::{
    enclave_dump_ra, enclave_init, enclave_mrenclave, enclave_perform_ra, enclave_shielding_key,
    enclave_signing_key,
};
use enclave::tls_ra::{enclave_request_key_provisioning, enclave_run_key_provisioning_server};
use sp_finality_grandpa::{AuthorityList, VersionedAuthorityList, GRANDPA_AUTHORITIES_KEY};
use substratee_node_primitives::calls::get_first_worker_that_is_not_equal_to_self;
use substratee_worker_api::Api as WorkerApi;
use ws_server::start_ws_server;

mod constants;
mod enclave;
mod ipfs;
mod tests;
mod ws_server;

fn main() {
    // Setup logging
    env_logger::init();

    let yml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yml).get_matches();

    let node_ip = matches.value_of("node-server").unwrap_or("ws://127.0.0.1");
    let node_port = matches.value_of("node-port").unwrap_or("9944");
    let n_url = format!("{}:{}", node_ip, node_port);
    info!("Interacting with node on {}", n_url);
    *NODE_URL.lock().unwrap() = n_url;

    let w_ip = matches.value_of("w-server").unwrap_or("127.0.0.1");
    let w_port = matches.value_of("w-port").unwrap_or("2000");
    info!("Worker listening on {}:{}", w_ip, w_port);

    let mu_ra_port = matches.value_of("mu-ra-port").unwrap_or("3443");
    info!("MU-RA server on port {}", mu_ra_port);

    if let Some(_matches) = matches.subcommand_matches("run") {
        println!("*** Starting substraTEE-worker");
        let shard: ShardIdentifier = match _matches.value_of("shard") {
            Some(value) => {
                let shard_vec = value.from_base58().unwrap();
                let mut shard = [0u8; 32];
                shard.copy_from_slice(&shard_vec[..]);
                shard.into()
            }
            _ => {
                let enclave = enclave_init().unwrap();
                let mrenclave = enclave_mrenclave(enclave.geteid()).unwrap();
                info!(
                    "no shard specified. using mrenclave as id: {}",
                    mrenclave.to_base58()
                );
                ShardIdentifier::from_slice(&mrenclave[..])
            }
        };
        worker(w_ip, w_port, mu_ra_port, &shard);
    } else if matches.is_present("shielding-key") {
        info!("*** Get the public key from the TEE\n");
        let enclave = enclave_init().unwrap();
        let pubkey = enclave_shielding_key(enclave.geteid()).unwrap();
        let file = File::create(constants::SHIELDING_KEY_FILE).unwrap();
        match serde_json::to_writer(file, &pubkey) {
            Err(x) => {
                error!(
                    "[-] Failed to write '{}'. {}",
                    constants::SHIELDING_KEY_FILE,
                    x
                );
            }
            _ => {
                println!(
                    "[+] File '{}' written successfully",
                    constants::SHIELDING_KEY_FILE
                );
            }
        }
        return;
    } else if matches.is_present("signing-key") {
        info!("*** Get the signing key from the TEE\n");
        let enclave = enclave_init().unwrap();
        let pubkey = enclave_signing_key(enclave.geteid()).unwrap();
        debug!("[+] Signing key raw: {:?}", pubkey);
        match fs::write(constants::SIGNING_KEY_FILE, pubkey) {
            Err(x) => {
                error!(
                    "[-] Failed to write '{}'. {}",
                    constants::SIGNING_KEY_FILE,
                    x
                );
            }
            _ => {
                println!(
                    "[+] File '{}' written successfully",
                    constants::SIGNING_KEY_FILE
                );
            }
        }
        return;
    } else if matches.is_present("dump-ra") {
        info!("*** Perform RA and dump cert to disk");
        let enclave = enclave_init().unwrap();
        enclave_dump_ra(enclave.geteid()).unwrap();
        return;
    } else if matches.is_present("mrenclave") {
        let enclave = enclave_init().unwrap();
        println!(
            "{}",
            enclave_mrenclave(enclave.geteid())
                .unwrap()
                .encode()
                .to_base58()
        );
        return;
    }
    if let Some(_matches) = matches.subcommand_matches("init-shard") {
        match _matches.values_of("shard") {
            Some(values) => {
                for shard in values {
                    match shard.from_base58() {
                        Ok(s) => {
                            init_shard(&ShardIdentifier::from_slice(&s[..]));
                        }
                        _ => panic!("shard must be hex encoded"),
                    }
                }
            }
            _ => {
                let enclave = enclave_init().unwrap();
                let shard =
                    ShardIdentifier::from_slice(&enclave_mrenclave(enclave.geteid()).unwrap());
                init_shard(&shard);
            }
        };
    } else if let Some(_matches) = matches.subcommand_matches("test") {
        if _matches.is_present("provisioning-server") {
            println!("*** Running Enclave MU-RA TLS server\n");
            let enclave = enclave_init().unwrap();
            enclave_run_key_provisioning_server(
                enclave.geteid(),
                sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
                &format!("localhost:{}", mu_ra_port),
            );
            println!("[+] Done!");
            enclave.destroy();
        } else if _matches.is_present("provisioning-client") {
            println!("*** Running Enclave MU-RA TLS client\n");
            let enclave = enclave_init().unwrap();
            enclave_request_key_provisioning(
                enclave.geteid(),
                sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
                &format!("localhost:{}", mu_ra_port),
            )
            .unwrap();
            println!("[+] Done!");
            enclave.destroy();
        } else {
            tests::run_enclave_tests(_matches, node_port);
        }
    } else {
        println!("For options: use --help");
    }
}

fn worker(w_ip: &str, w_port: &str, mu_ra_port: &str, shard: &ShardIdentifier) {
    info!("starting worker on shard {}", shard.encode().to_base58());
    // ------------------------------------------------------------------------
    // check for required files
    check_files();
    // ------------------------------------------------------------------------
    // initialize the enclave
    #[cfg(feature = "production")]
    println!("*** Starting enclave in production mode");
    #[cfg(not(feature = "production"))]
    println!("*** Starting enclave in development mode");

    let enclave = enclave_init().unwrap();
    let eid = enclave.geteid();
    // ------------------------------------------------------------------------
    // start the ws server to listen for worker requests
    let w_url = format!("{}:{}", w_ip, w_port);
    start_ws_server(eid, w_url.clone(), mu_ra_port.to_string());

    // ------------------------------------------------------------------------
    // let new workers call us for key provisioning
    let eid = enclave.geteid();
    let ra_url = format!("{}:{}", w_ip, mu_ra_port);
    thread::spawn(move || {
        enclave_run_key_provisioning_server(
            eid,
            sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
            &ra_url,
        )
    });

    // ------------------------------------------------------------------------
    // start the substrate-api-client to communicate with the node
    let mut api =
        Api::new(NODE_URL.lock().unwrap().clone()).set_signer(AccountKeyring::Alice.pair());
    let genesis_hash = api.genesis_hash.as_bytes().to_vec();

    let tee_accountid = enclave_account(eid);
    ensure_account_has_funds(&mut api, &tee_accountid);

    // ------------------------------------------------------------------------
    // perform a remote attestation and get an unchecked extrinsic back

    // get enclaves's account nonce
    let nonce = get_nonce(&api, &tee_accountid);
    info!("Enclave nonce = {:?}", nonce);

    let uxt = enclave_perform_ra(eid, genesis_hash, nonce, w_url.as_bytes().to_vec()).unwrap();

    let ue = UncheckedExtrinsic::decode(&mut uxt.as_slice()).unwrap();
    let mut _xthex = hex::encode(ue.encode());
    _xthex.insert_str(0, "0x");

    // send the extrinsic and wait for confirmation
    println!("[>] Register the enclave (send the extrinsic)");
    let tx_hash = api.send_extrinsic(_xthex, XtStatus::InBlock).unwrap();
    println!("[<] Extrinsic got finalized. Hash: {:?}\n", tx_hash);

    // browse enclave registry
    match get_first_worker_that_is_not_equal_to_self(&api, &tee_accountid) {
        Some(w) => {
            let _url = String::from_utf8_lossy(&w.url[..]).to_string();
            let _w_api = WorkerApi::new(_url.clone());
            let _url_split: Vec<_> = _url.split(':').collect();
            let mura_url = format!("{}:{}", _url_split[0], _w_api.get_mu_ra_port().unwrap());

            info!("Requesting key provisioning from worker at {}", mura_url);
            enclave_request_key_provisioning(
                eid,
                sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
                &mura_url,
            )
            .unwrap();
            debug!("key provisioning successfully performed");
        }
        None => {
            info!("there are no other workers");
        }
    }

    println!("*** [+] finished remote attestation\n");

    println!("*** Syncing chain relay\n\n");
    let mut latest_head = init_chain_relay(eid, &api);
    println!("*** [+] Finished syncing chain relay\n");

    // ------------------------------------------------------------------------
    // subscribe to events and react on firing
    println!("*** Subscribing to events");
    let (sender, receiver) = channel();
    let sender2 = sender.clone();
    let api2 = api.clone();
    let _eventsubscriber = thread::Builder::new()
        .name("eventsubscriber".to_owned())
        .spawn(move || {
            api2.subscribe_events(sender2);
        })
        .unwrap();

    let api3 = api.clone();
    let sender3 = sender.clone();
    let _block_subscriber = thread::Builder::new()
        .name("block_subscriber".to_owned())
        .spawn(move || api3.subscribe_finalized_heads(sender3))
        .unwrap();

    println!("[+] Subscribed to events. waiting...");

    loop {
        let msg = receiver.recv().unwrap();
        if let Ok(events) = parse_events(msg.clone()) {
            print_events(events, sender.clone())
        } else if let Ok(_header) = parse_header(msg.clone()) {
            latest_head = sync_chain_relay(eid, &api, latest_head)
        } else {
            println!("[-] Unable to parse received message!")
        }
    }
}

type Events = Vec<frame_system::EventRecord<Event, Hash>>;

fn parse_events(event: String) -> Result<Events, String> {
    let _unhex = hexstr_to_vec(event).map_err(|_| "Decoding Events Failed".to_string())?;
    let mut _er_enc = _unhex.as_slice();
    Events::decode(&mut _er_enc).map_err(|_| "Decoding Events Failed".to_string())
}

fn parse_header(header: String) -> Result<Header, String> {
    serde_json::from_str(&header).map_err(|_| "Decoding Header Failed".to_string())
}

fn print_events(events: Events, _sender: Sender<String>) {
    for evr in &events {
        debug!("Decoded: phase = {:?}, event = {:?}", evr.phase, evr.event);
        match &evr.event {
            Event::balances(be) => {
                println!("[+] Received balances event");
                debug!("{:?}", be);
                match &be {
                    pallet_balances::RawEvent::Transfer(transactor, dest, value) => {
                        println!("    Transactor:  {:?}", transactor.to_ss58check());
                        println!("    Destination: {:?}", dest.to_ss58check());
                        println!("    Value:       {:?}", value);
                        println!();
                    }
                    _ => {
                        info!("Ignoring unsupported balances event");
                    }
                }
            }
            Event::substratee_registry(re) => {
                debug!("{:?}", re);
                match &re {
                    substratee_node_runtime::substratee_registry::RawEvent::AddedEnclave(
                        sender,
                        worker_url,
                    ) => {
                        println!("[+] Received AddedEnclave event");
                        println!("    Sender (Worker):  {:?}", sender);
                        println!(
                            "    Registered URL: {:?}",
                            str::from_utf8(worker_url).unwrap()
                        );
                        println!();
                    }
                    substratee_node_runtime::substratee_registry::RawEvent::Forwarded(request) => {
                        println!("[+] Received trusted call");
                        info!(
                            "    Request: \n  shard: {}\n  cyphertext: {:?}",
                            request.shard.encode().to_base58(),
                            request.cyphertext.clone()
                        );
                    }
                    substratee_node_runtime::substratee_registry::RawEvent::CallConfirmed(
                        sender,
                        payload,
                    ) => {
                        println!("[+] Received CallConfirmed event");
                        debug!("    From:    {:?}", sender);
                        debug!("    Payload: {:?}", hex::encode(payload));
                        println!();
                    }
                    substratee_node_runtime::substratee_registry::RawEvent::ShieldFunds(
                        incognito_account,
                    ) => {
                        println!("[+] Received ShieldFunds event");
                        debug!("    For:    {:?}", incognito_account);
                        println!();
                    }
                    substratee_node_runtime::substratee_registry::RawEvent::UnshieldedFunds(
                        incognito_account,
                    ) => {
                        println!("[+] Received UnshieldedFunds event");
                        debug!("    For:    {:?}", incognito_account);
                        println!();
                    }
                    _ => {
                        info!("Ignoring unsupported substratee_registry event");
                    }
                }
            }
            _ => {
                info!("Ignoring event {:?}", evr);
            }
        }
    }
}

pub fn init_chain_relay(eid: sgx_enclave_id_t, api: &Api<sr25519::Pair>) -> Header {
    let genesis_hash = api.get_genesis_hash();
    let genesis_header: Header = api.get_header(Some(genesis_hash)).unwrap();
    info!("Got genesis Header: \n {:?} \n", genesis_header);
    let grandpas: AuthorityList = api
        .get_storage_by_key_hash(
            StorageKey(GRANDPA_AUTHORITIES_KEY.to_vec()),
            Some(genesis_header.hash()),
        )
        .map(|g: VersionedAuthorityList| g.into())
        .unwrap();

    let grandpa_proof = api
        .get_storage_proof_by_keys(
            vec![StorageKey(GRANDPA_AUTHORITIES_KEY.to_vec())],
            Some(genesis_header.hash()),
        )
        .map(|read_proof| read_proof.proof.into_iter().map(|bytes| bytes.0).collect())
        .unwrap();

    debug!("Grandpa Authority List: \n {:?} \n ", grandpas);

    let latest = enclave_init_chain_relay(
        eid,
        genesis_header,
        VersionedAuthorityList::from(grandpas),
        grandpa_proof,
    )
    .unwrap();

    info!("Finished initializing chain relay, syncing....");

    sync_chain_relay(eid, api, latest)
}

pub fn sync_chain_relay(
    eid: sgx_enclave_id_t,
    api: &Api<sr25519::Pair>,
    last_synced_head: Header,
) -> Header {
    // obtain latest finalized block
    let curr_head: SignedBlock = api
        .get_finalized_head()
        .map(|hash| api.get_signed_block(Some(hash)).unwrap())
        .unwrap();

    if curr_head.block.header.hash() == last_synced_head.hash() {
        // we are already up to date, do nothing
        return curr_head.block.header;
    }

    let mut blocks_to_sync = Vec::<SignedBlock>::new();
    blocks_to_sync.push(curr_head.clone());

    // Todo: Check, is this dangerous such that it could be an eternal or too big loop?
    let mut head = curr_head.clone();

    let no_blocks_to_sync = head.block.header.number - last_synced_head.number;
    if no_blocks_to_sync > 1 {
        println!("Chain Relay is synced until block: {:?}", last_synced_head.number);
        println!("Last finalized block number: {:?}\n", head.block.header.number);
    }

    while head.block.header.parent_hash != last_synced_head.hash() {
        head = api
            .get_signed_block(Some(head.block.header.parent_hash))
            .unwrap();
        blocks_to_sync.push(head.clone());

        if head.block.header.number % 100 == 0 {
            println!("Remaining blocks to fetch until last synced header: {:?}", head.block.header.number - last_synced_head.number)
        }
    }
    blocks_to_sync.reverse();

    let tee_accountid = enclave_account(eid);

    // only feed 100 blocks at a time into the enclave to save enclave state regularly
    let mut i = blocks_to_sync[0].block.header.number as usize;
    for chunk in blocks_to_sync.chunks(100) {
        let tee_nonce = get_nonce(&api, &tee_accountid);
        let xts = enclave_sync_chain_relay(eid, chunk.to_vec(), tee_nonce).unwrap();
        let extrinsics: Vec<Vec<u8>> = Decode::decode(&mut xts.as_slice()).unwrap();

        if !extrinsics.is_empty() {
            println!(
                "Sync chain relay: Enclave wants to send {} extrinsics",
                extrinsics.len()
            );
        }
        for xt in extrinsics.into_iter() {
            api.send_extrinsic(hex_encode(xt), XtStatus::InBlock)
                .unwrap();
        }

        i += chunk.len();
        println!("Synced {} blocks out of {} finalized blocks", i ,  blocks_to_sync[0].block.header.number as usize + blocks_to_sync.len())
    }

    curr_head.block.header
}

fn hex_encode(data: Vec<u8>) -> String {
    let mut hex_str = hex::encode(data);
    hex_str.insert_str(0, "0x");
    hex_str
}

fn init_shard(shard: &ShardIdentifier) {
    let path = format!("{}/{}", constants::SHARDS_PATH, shard.encode().to_base58());
    println!("initializing shard at {}", path);
    fs::create_dir_all(path.clone()).expect("could not create dir");

    let path = format!("{}/{}", path, constants::ENCRYPTED_STATE_FILE);
    if Path::new(&path).exists() {
        println!("shard state exists. Overwrite? [y/N]");
        let buffer = &mut String::new();
        stdin().read_line(buffer).unwrap();
        match buffer.trim() {
            "y" | "Y" => (),
            _ => return,
        }
    }
    let mut file = fs::File::create(path).unwrap();
    file.write_all(b"").unwrap();
}

// get the public signing key of the TEE
fn enclave_account(eid: sgx_enclave_id_t) -> AccountId32 {
    let tee_public = enclave_signing_key(eid).unwrap();
    info!(
        "[+] Got ed25519 account of TEE = {}",
        tee_public.to_ss58check()
    );
    AccountId32::from(*tee_public.as_array_ref())
}

// Alice plays the faucet and sends some funds to the account if balance is low
fn ensure_account_has_funds(api: &mut Api<sr25519::Pair>, accountid: &AccountId32) {
    let alice = AccountKeyring::Alice.pair();
    info!("encoding Alice's public 	= {:?}", alice.public().0.encode());
    let alice_acc = AccountId32::from(*alice.public().as_array_ref());
    info!("encoding Alice's AccountId = {:?}", alice_acc.encode());

    let free = get_balance(&api, &alice_acc);
    info!("    Alice's free balance = {:?}", free);
    let nonce = get_nonce(&api, &alice_acc);
    info!("    Alice's Account Nonce is {}", nonce);

    // check account balance
    let free = get_balance(&api, &accountid);
    info!("TEE's free balance = {:?}", free);

    if free < 1_000_000_000_000 {
        let signer_orig = api.signer.clone();
        api.signer = Some(alice);

        println!("[+] bootstrap funding Enclave form Alice's funds");
        let xt = api.balance_transfer(accountid.clone(), 1_000_000_000_000);
        let xt_hash = api
            .send_extrinsic(xt.hex_encode(), XtStatus::InBlock)
            .unwrap();
        info!("[<] Extrinsic got finalized. Hash: {:?}\n", xt_hash);

        //verify funds have arrived
        let free = get_balance(&api, &accountid);
        info!("TEE's NEW free balance = {:?}", free);

        api.signer = signer_orig;
    }
}

fn get_nonce(api: &Api<sr25519::Pair>, who: &AccountId32) -> u32 {
    if let Some(info) = api.get_account_info(who) {
        info.nonce
    } else {
        0
    }
}

fn get_balance(api: &Api<sr25519::Pair>, who: &AccountId32) -> u128 {
    if let Some(data) = api.get_account_data(who) {
        data.free
    } else {
        0
    }
}

pub fn check_files() {
    debug!("*** Check files");
    let files = vec![
        constants::ENCLAVE_FILE,
        constants::SHIELDING_KEY_FILE,
        constants::SIGNING_KEY_FILE,
        constants::RA_SPID_FILE,
        constants::RA_API_KEY_FILE,
    ];
    for f in files.iter() {
        if !Path::new(f).exists() {
            panic!("file doesn't exist: {}", f);
        }
    }
}

lazy_static! {
    // todo: replace with &str, but use &str in api-client first
    static ref NODE_URL: Mutex<String> = Mutex::new("".to_string());
}

/// # Safety
///
/// FFI are always unsafe
#[no_mangle]
pub unsafe extern "C" fn ocall_worker_request(
    request: *const u8,
    req_size: u32,
    response: *mut u8,
    resp_size: u32,
) -> sgx_status_t {
    debug!("    Entering ocall_worker_request");
    let mut req_slice = slice::from_raw_parts(request, req_size as usize);
    let resp_slice = slice::from_raw_parts_mut(response, resp_size as usize);

    let api = Api::<sr25519::Pair>::new(NODE_URL.lock().unwrap().clone());

    let requests: Vec<WorkerRequest> = Decode::decode(&mut req_slice).unwrap();

    let resp: Vec<WorkerResponse<Vec<u8>>> = requests
        .into_iter()
        .map(|req| match req {
            //let res =
            WorkerRequest::ChainStorage(key, hash) => WorkerResponse::ChainStorage(
                key.clone(),
                api.get_opaque_storage_by_key_hash(StorageKey(key.clone()), hash),
                api.get_storage_proof_by_keys(vec![StorageKey(key)], hash)
                    .map(|read_proof| read_proof.proof.into_iter().map(|bytes| bytes.0).collect()),
            ),
        })
        .collect();

    write_slice_and_whitespace_pad(resp_slice, resp.encode());
    sgx_status_t::SGX_SUCCESS
}

pub fn write_slice_and_whitespace_pad(writable: &mut [u8], data: Vec<u8>) {
    if data.len() > writable.len() {
        panic!("not enough bytes in output buffer for return value");
    }
    let (left, right) = writable.split_at_mut(data.len());
    left.clone_from_slice(&data);
    // fill the right side with whitespace
    right.iter_mut().for_each(|x| *x = 0x20);
}

#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub enum WorkerRequest {
    ChainStorage(Vec<u8>, Option<Hash>), // (storage_key, at_block)
}

#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub enum WorkerResponse<V: Encode + Decode> {
    ChainStorage(Vec<u8>, Option<V>, Option<Vec<Vec<u8>>>), // (storage_key, storage_value, storage_proof)
}
