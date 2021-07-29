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
use crate::{
	direct_invocation::{
		watch_list_service::{WatchList, WatchListService},
		watching_client::WsWatchingClient,
		ws_direct_server_runner::{RunWsServer, WsDirectServerRunner},
		ws_handler::WsHandlerFactory,
	},
	globals::{
		tokio_handle::{GetTokioHandle, GlobalTokioHandle},
		worker::{GlobalWorker, Worker},
	},
	node_api_factory::{CreateNodeApi, GlobalUrlNodeApiFactory},
	ocall_bridge::{
		bridge_api::Bridge as OCallBridge, component_factory::OCallBridgeComponentFactory,
	},
	sync_block_gossiper::SyncBlockGossiper,
	utils::{check_files, extract_shard},
	worker::worker_url_into_async_rpc_url,
};
use base58::ToBase58;
use clap::{load_yaml, App};
use codec::{Decode, Encode};
use config::Config;
use enclave::{
	api::enclave_init,
	tls_ra::{enclave_request_key_provisioning, enclave_run_key_provisioning_server},
};
use log::*;
use my_node_runtime::{substratee_registry::ShardIdentifier, Event, Hash, Header};
use sgx_types::*;
use sp_core::{
	crypto::{AccountId32, Ss58Codec},
	sr25519, Pair,
};
use sp_finality_grandpa::VersionedAuthorityList;
use sp_keyring::AccountKeyring;
use std::{
	fs::{self, File},
	io::{stdin, Write},
	path::Path,
	str,
	sync::{
		mpsc::{channel, Sender},
		Arc,
	},
	thread,
	time::{Duration, SystemTime},
};
use substrate_api_client::{utils::FromHexString, Api, GenericAddress, XtStatus};
use substratee_api_client_extensions::{AccountApi, ChainApi};
use substratee_enclave_api::{
	direct_request::DirectRequest,
	enclave_base::EnclaveBase,
	remote_attestation::{RemoteAttestation, TlsRemoteAttestation},
	side_chain::SideChain,
	teerex_api::TeerexApi,
};
use substratee_node_primitives::SignedBlock;
use substratee_settings::files::{
	ENCRYPTED_STATE_FILE, SHARDS_PATH, SHIELDING_KEY_FILE, SIGNING_KEY_FILE,
};
use substratee_worker_api::direct_client::DirectClient;

mod config;
mod direct_invocation;
mod enclave;
mod error;
mod globals;
mod node_api_factory;
mod ocall_bridge;
mod sync_block_gossiper;
mod tests;
mod utils;
mod worker;

/// how many blocks will be synced before storing the chain db to disk
const BLOCK_SYNC_BATCH_SIZE: u32 = 1000;
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// start block production every ... ms
const BLOCK_PRODUCTION_INTERVAL: u64 = 1000;

fn main() {
	// Setup logging
	env_logger::init();

	let yml = load_yaml!("cli.yml");
	let matches = App::from_yaml(yml).get_matches();

	let mut config = Config::from(&matches);

	GlobalTokioHandle::initialize();

	// build the entire dependency tree
	let worker = Arc::new(GlobalWorker {});
	let tokio_handle = Arc::new(GlobalTokioHandle {});
	let sync_block_gossiper = Arc::new(SyncBlockGossiper::new(tokio_handle.clone(), worker));
	let node_api_factory = Arc::new(GlobalUrlNodeApiFactory::new(config.node_url()));
	let direct_invocation_watch_list = Arc::new(WatchListService::<WsWatchingClient>::new());
	let enclave = Arc::new(enclave_init().unwrap());

	// initialize o-call bridge with a concrete factory implementation
	OCallBridge::initialize(Arc::new(OCallBridgeComponentFactory::new(
		node_api_factory.clone(),
		sync_block_gossiper,
		direct_invocation_watch_list.clone(),
		enclave.clone(),
	)));

	if let Some(smatches) = matches.subcommand_matches("run") {
		println!("*** Starting substraTEE-worker");
		let shard = extract_shard(&smatches, enclave.as_ref());

		// Todo: Is this deprecated?? It is only used in remote attestation.
		config.set_ext_api_url(
			smatches
				.value_of("w-server")
				.map(ToString::to_string)
				.unwrap_or_else(|| format!("ws://127.0.0.1:{}", config.worker_rpc_port)),
		);

		println!("Worker Config: {:?}", config);
		let skip_ra = smatches.is_present("skip-ra");

		let node_api = node_api_factory.create_api().set_signer(AccountKeyring::Alice.pair());

		GlobalWorker::reset_worker(Worker::new(
			config.clone(),
			node_api.clone(),
			enclave.clone(),
			DirectClient::new(config.worker_url()),
		));

		start_worker(
			config,
			&shard,
			enclave,
			skip_ra,
			node_api,
			tokio_handle,
			direct_invocation_watch_list,
		);
	} else if let Some(smatches) = matches.subcommand_matches("request-keys") {
		let shard = extract_shard(&smatches, enclave.as_ref());
		let provider_url = smatches.value_of("provider").expect("provider must be specified");
		request_keys(provider_url, &shard, enclave.as_ref(), smatches.is_present("skip-ra"));
	} else if matches.is_present("shielding-key") {
		info!("*** Get the public key from the TEE\n");
		let pubkey = enclave.get_rsa_shielding_pubkey().unwrap();
		let file = File::create(SHIELDING_KEY_FILE).unwrap();
		match serde_json::to_writer(file, &pubkey) {
			Err(x) => {
				error!("[-] Failed to write '{}'. {}", SHIELDING_KEY_FILE, x);
			},
			_ => {
				println!("[+] File '{}' written successfully", SHIELDING_KEY_FILE);
			},
		}
	} else if matches.is_present("signing-key") {
		info!("*** Get the signing key from the TEE\n");
		let pubkey = enclave.get_ecc_signing_pubkey().unwrap();
		debug!("[+] Signing key raw: {:?}", pubkey);
		match fs::write(SIGNING_KEY_FILE, pubkey) {
			Err(x) => {
				error!("[-] Failed to write '{}'. {}", SIGNING_KEY_FILE, x);
			},
			_ => {
				println!("[+] File '{}' written successfully", SIGNING_KEY_FILE);
			},
		}
	} else if matches.is_present("dump-ra") {
		info!("*** Perform RA and dump cert to disk");
		enclave.dump_ra_to_disk().unwrap();
	} else if matches.is_present("mrenclave") {
		println!("{}", enclave.get_mrenclave().unwrap().encode().to_base58());
	} else if let Some(_matches) = matches.subcommand_matches("init-shard") {
		let shard = extract_shard(&_matches, enclave.as_ref());
		init_shard(&shard);
	} else if let Some(_matches) = matches.subcommand_matches("test") {
		if _matches.is_present("provisioning-server") {
			println!("*** Running Enclave MU-RA TLS server\n");
			enclave_run_key_provisioning_server(
				enclave.as_ref(),
				sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
				&format!("localhost:{}", config.worker_mu_ra_port),
				_matches.is_present("skip-ra"),
			);
			println!("[+] Done!");
		} else if _matches.is_present("provisioning-client") {
			println!("*** Running Enclave MU-RA TLS client\n");
			enclave_request_key_provisioning(
				enclave.as_ref(),
				sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
				&format!("localhost:{}", config.worker_mu_ra_port),
				_matches.is_present("skip-ra"),
			)
			.unwrap();
			println!("[+] Done!");
		} else {
			tests::run_enclave_tests(_matches, &config.node_port);
		}
	} else {
		println!("For options: use --help");
	}
}

fn start_worker<E, T, W>(
	config: Config,
	shard: &ShardIdentifier,
	enclave: Arc<E>,
	skip_ra: bool,
	mut node_api: Api<sr25519::Pair>,
	tokio_handle: Arc<T>,
	watch_list: Arc<W>,
) where
	T: GetTokioHandle,
	W: WatchList<Client = WsWatchingClient>,
	E: EnclaveBase
		+ DirectRequest
		+ SideChain
		+ RemoteAttestation
		+ TlsRemoteAttestation
		+ TeerexApi
		+ Clone,
{
	println!("IntegriTEE Worker v{}", VERSION);
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

	let mrenclave = enclave.get_mrenclave().unwrap();
	println!("MRENCLAVE={}", mrenclave.to_base58());

	// ------------------------------------------------------------------------
	// let new workers call us for key provisioning
	println!("MU-RA server listening on ws://{}", config.mu_ra_url());
	let ra_url = config.mu_ra_url();
	let enclave_api_key_prov = enclave.clone();
	thread::spawn(move || {
		enclave_run_key_provisioning_server(
			enclave_api_key_prov.as_ref(),
			sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
			&ra_url,
			skip_ra,
		)
	});

	// ------------------------------------------------------------------------
	// start worker api direct invocation server
	println!("rpc worker server listening on ws://{}", config.worker_url());

	let ws_handler_factory = Arc::new(WsHandlerFactory::new(enclave.clone(), watch_list));
	let ws_direct_server = WsDirectServerRunner::new(ws_handler_factory, enclave.clone());
	ws_direct_server.run(config.worker_url());

	// listen for sidechain_block import request. Later the `start_worker_api_direct_server`
	// should be merged into this one.
	let url = worker_url_into_async_rpc_url(&config.worker_url()).unwrap();

	let handle = tokio_handle.get_handle();
	let enclave_rpc_server = enclave.clone();
	handle.spawn(async move {
		substratee_worker_rpc_server::run_server(&url, enclave_rpc_server)
			.await
			.unwrap()
	});
	// ------------------------------------------------------------------------
	// start the substrate-api-client to communicate with the node
	let genesis_hash = node_api.genesis_hash.as_bytes().to_vec();

	let tee_accountid = enclave_account(enclave.as_ref());
	ensure_account_has_funds(&mut node_api, &tee_accountid);

	// ------------------------------------------------------------------------
	// perform a remote attestation and get an unchecked extrinsic back

	// get enclaves's account nonce
	let nonce = node_api.get_nonce_of(&tee_accountid).unwrap();
	info!("Enclave nonce = {:?}", nonce);

	let uxt = if skip_ra {
		println!(
			"[!] skipping remote attestation. Registering enclave without attestation report."
		);
		enclave
			.mock_register_xt(node_api.genesis_hash, nonce, &config.ext_api_url.unwrap())
			.unwrap()
	} else {
		enclave
			.perform_ra(genesis_hash, nonce, config.ext_api_url.unwrap().as_bytes().to_vec())
			.unwrap()
	};

	let mut xthex = hex::encode(uxt);
	xthex.insert_str(0, "0x");

	// send the extrinsic and wait for confirmation
	println!("[>] Register the enclave (send the extrinsic)");
	let tx_hash = node_api.send_extrinsic(xthex, XtStatus::Finalized).unwrap();
	println!("[<] Extrinsic got finalized. Hash: {:?}\n", tx_hash);

	let latest_head = init_chain_relay(&node_api, enclave.as_ref());
	println!("*** [+] Finished syncing chain relay\n");

	// ------------------------------------------------------------------------
	// start interval block production
	let api4 = node_api.clone();
	thread::Builder::new()
		.name("interval_block_production_timer".to_owned())
		.spawn(move || {
			start_interval_block_production(enclave.clone().as_ref(), &api4, latest_head)
		})
		.unwrap();

	// ------------------------------------------------------------------------
	// subscribe to events and react on firing
	println!("*** Subscribing to events");
	let (sender, receiver) = channel();
	let sender2 = sender.clone();
	let _eventsubscriber = thread::Builder::new()
		.name("eventsubscriber".to_owned())
		.spawn(move || {
			node_api.subscribe_events(sender2).unwrap();
		})
		.unwrap();

	println!("[+] Subscribed to events. waiting...");
	let timeout = Duration::from_millis(10);
	loop {
		if let Ok(msg) = receiver.recv_timeout(timeout) {
			if let Ok(events) = parse_events(msg.clone()) {
				print_events(events, sender.clone())
			}
		}
	}
}

/// Triggers the enclave to produce a block based on a fixed time schedule
fn start_interval_block_production<E: EnclaveBase + SideChain>(
	enclave_api: &E,
	api: &Api<sr25519::Pair>,
	mut latest_head: Header,
) {
	let block_production_interval = Duration::from_millis(BLOCK_PRODUCTION_INTERVAL);
	let mut interval_start = SystemTime::now();
	loop {
		if let Ok(elapsed) = interval_start.elapsed() {
			if elapsed >= block_production_interval {
				// update interval time
				interval_start = SystemTime::now();
				latest_head = produce_blocks(enclave_api, api, latest_head)
			} else {
				// sleep for the rest of the interval
				let sleep_time = block_production_interval - elapsed;
				thread::sleep(sleep_time);
			}
		}
	}
}

fn request_keys<E: TlsRemoteAttestation>(
	provider_url: &str,
	_shard: &ShardIdentifier,
	enclave_api: &E,
	skip_ra: bool,
) {
	// FIXME: we now assume that keys are equal for all shards

	// initialize the enclave
	#[cfg(feature = "production")]
	println!("*** Starting enclave in production mode");
	#[cfg(not(feature = "production"))]
	println!("*** Starting enclave in development mode");

	println!("Requesting key provisioning from worker at {}", provider_url);

	enclave_request_key_provisioning(
		enclave_api,
		sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
		&provider_url,
		skip_ra,
	)
	.unwrap();
	println!("key provisioning successfully performed");
}

type Events = Vec<frame_system::EventRecord<Event, Hash>>;

fn parse_events(event: String) -> Result<Events, String> {
	let _unhex = Vec::from_hex(event).map_err(|_| "Decoding Events Failed".to_string())?;
	let mut _er_enc = _unhex.as_slice();
	Events::decode(&mut _er_enc).map_err(|_| "Decoding Events Failed".to_string())
}

fn print_events(events: Events, _sender: Sender<String>) {
	for evr in &events {
		debug!("Decoded: phase = {:?}, event = {:?}", evr.phase, evr.event);
		match &evr.event {
			Event::Balances(be) => {
				info!("[+] Received balances event");
				debug!("{:?}", be);
				match &be {
					pallet_balances::Event::Transfer(transactor, dest, value) => {
						debug!("    Transactor:  {:?}", transactor.to_ss58check());
						debug!("    Destination: {:?}", dest.to_ss58check());
						debug!("    Value:       {:?}", value);
					},
					_ => {
						trace!("Ignoring unsupported balances event");
					},
				}
			},
			Event::SubstrateeRegistry(re) => {
				debug!("{:?}", re);
				match &re {
					my_node_runtime::substratee_registry::RawEvent::AddedEnclave(
						sender,
						worker_url,
					) => {
						println!("[+] Received AddedEnclave event");
						println!("    Sender (Worker):  {:?}", sender);
						println!("    Registered URL: {:?}", str::from_utf8(worker_url).unwrap());
					},
					my_node_runtime::substratee_registry::RawEvent::Forwarded(shard) => {
						println!(
							"[+] Received trusted call for shard {}",
							shard.encode().to_base58()
						);
					},
					my_node_runtime::substratee_registry::RawEvent::CallConfirmed(
						sender,
						payload,
					) => {
						info!("[+] Received CallConfirmed event");
						debug!("    From:    {:?}", sender);
						debug!("    Payload: {:?}", hex::encode(payload));
					},
					my_node_runtime::substratee_registry::RawEvent::BlockConfirmed(
						sender,
						payload,
					) => {
						info!("[+] Received BlockConfirmed event");
						debug!("    From:    {:?}", sender);
						debug!("    Payload: {:?}", hex::encode(payload));
					},
					my_node_runtime::substratee_registry::RawEvent::ShieldFunds(
						incognito_account,
					) => {
						info!("[+] Received ShieldFunds event");
						debug!("    For:    {:?}", incognito_account);
					},
					my_node_runtime::substratee_registry::RawEvent::UnshieldedFunds(
						incognito_account,
					) => {
						info!("[+] Received UnshieldedFunds event");
						debug!("    For:    {:?}", incognito_account);
					},
					_ => {
						trace!("Ignoring unsupported substratee_registry event");
					},
				}
			},
			_ => {
				trace!("Ignoring event {:?}", evr);
			},
		}
	}
}

pub fn init_chain_relay<E: EnclaveBase + SideChain>(
	api: &Api<sr25519::Pair>,
	enclave_api: &E,
) -> Header {
	let genesis_hash = api.get_genesis_hash().unwrap();
	let genesis_header: Header = api.get_header(Some(genesis_hash)).unwrap().unwrap();
	info!("Got genesis Header: \n {:?} \n", genesis_header);
	let grandpas = api.grandpa_authorities(Some(genesis_hash)).unwrap();
	let grandpa_proof = api.grandpa_authorities_proof(Some(genesis_hash)).unwrap();

	debug!("Grandpa Authority List: \n {:?} \n ", grandpas);

	let authority_list = VersionedAuthorityList::from(grandpas);

	let latest = enclave_api
		.init_chain_relay(genesis_header, authority_list, grandpa_proof)
		.unwrap();

	info!("Finished initializing chain relay, syncing....");

	produce_blocks(enclave_api, api, latest)
}

/// Starts block production
///
/// Returns the last synced header of layer one
pub fn produce_blocks<E: EnclaveBase + SideChain>(
	enclave_api: &E,
	api: &Api<sr25519::Pair>,
	last_synced_head: Header,
) -> Header {
	// obtain latest finalized block from layer one
	debug!("Getting current head");
	let curr_head: SignedBlock = api.last_finalized_block().unwrap().unwrap();

	let blocks_to_sync = get_blocks_to_sync(api, &last_synced_head, &curr_head);

	let tee_accountid = enclave_account(enclave_api);

	// only feed BLOCK_SYNC_BATCH_SIZE blocks at a time into the enclave to save enclave state regularly
	let mut current_block_number = if curr_head.block.header.hash() == last_synced_head.hash() {
		curr_head.block.header.number as usize
	} else {
		blocks_to_sync.first().map(|h| h.block.header.number as usize).unwrap_or(0)
	};

	for chunk in blocks_to_sync.chunks(BLOCK_SYNC_BATCH_SIZE as usize) {
		let tee_nonce = api.get_nonce_of(&tee_accountid).unwrap();

		// Produce blocks
		if let Err(e) = chunk
			.to_vec()
			.using_encoded(|b| enclave_api.produce_blocks(b.to_vec(), tee_nonce))
		{
			error!("{:?}", e);
			// enclave might not have synced
			return last_synced_head
		};

		current_block_number += chunk.len();
		println!(
			"Synced {} blocks out of {} finalized blocks",
			current_block_number,
			blocks_to_sync[0].block.header.number as usize + blocks_to_sync.len()
		)
	}

	curr_head.block.header
}

/// gets a list of blocks that need to be synced, ordered from oldest to most recent header
/// blocks that need to be synced are all blocks from the current header to the last synced header, iterating over parent
fn get_blocks_to_sync(
	api: &Api<sr25519::Pair>,
	last_synced_head: &Header,
	curr_head: &SignedBlock,
) -> Vec<SignedBlock> {
	let mut blocks_to_sync = Vec::<SignedBlock>::new();

	// add blocks to sync if not already up to date
	if curr_head.block.header.hash() != last_synced_head.hash() {
		blocks_to_sync.push((*curr_head).clone());

		// Todo: Check, is this dangerous such that it could be an eternal or too big loop?
		let mut head = (*curr_head).clone();
		let no_blocks_to_sync = head.block.header.number - last_synced_head.number;
		if no_blocks_to_sync > 1 {
			println!("Chain Relay is synced until block: {:?}", last_synced_head.number);
			println!("Last finalized block number: {:?}\n", head.block.header.number);
		}
		while head.block.header.parent_hash != last_synced_head.hash() {
			debug!("Getting head of hash: {:?}", head.block.header.parent_hash);
			head = api.signed_block(Some(head.block.header.parent_hash)).unwrap().unwrap();
			blocks_to_sync.push(head.clone());

			if head.block.header.number % BLOCK_SYNC_BATCH_SIZE == 0 {
				println!(
					"Remaining blocks to fetch until last synced header: {:?}",
					head.block.header.number - last_synced_head.number
				)
			}
		}
		blocks_to_sync.reverse();
	}
	blocks_to_sync
}

fn init_shard(shard: &ShardIdentifier) {
	let path = format!("{}/{}", SHARDS_PATH, shard.encode().to_base58());
	println!("initializing shard at {}", path);
	fs::create_dir_all(path.clone()).expect("could not create dir");

	let path = format!("{}/{}", path, ENCRYPTED_STATE_FILE);
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
fn enclave_account<E: EnclaveBase>(enclave_api: &E) -> AccountId32 {
	let tee_public = enclave_api.get_ecc_signing_pubkey().unwrap();
	trace!("[+] Got ed25519 account of TEE = {}", tee_public.to_ss58check());
	AccountId32::from(*tee_public.as_array_ref())
}

// Alice plays the faucet and sends some funds to the account if balance is low
fn ensure_account_has_funds(api: &mut Api<sr25519::Pair>, accountid: &AccountId32) {
	let alice = AccountKeyring::Alice.pair();
	info!("encoding Alice's public 	= {:?}", alice.public().0.encode());
	let alice_acc = AccountId32::from(*alice.public().as_array_ref());
	info!("encoding Alice's AccountId = {:?}", alice_acc.encode());

	let free = api.get_free_balance(&alice_acc);
	info!("    Alice's free balance = {:?}", free);
	let nonce = api.get_nonce_of(&alice_acc).unwrap();
	info!("    Alice's Account Nonce is {}", nonce);

	// check account balance
	let free = api.get_free_balance(&accountid).unwrap();
	info!("TEE's free balance = {:?}", free);

	if free < 1_000_000_000_000 {
		let signer_orig = api.signer.clone();
		api.signer = Some(alice);

		println!("[+] bootstrap funding Enclave form Alice's funds");
		let xt = api.balance_transfer(GenericAddress::Id(accountid.clone()), 1_000_000_000_000);
		let xt_hash = api.send_extrinsic(xt.hex_encode(), XtStatus::InBlock).unwrap();
		info!("[<] Extrinsic got finalized. Hash: {:?}\n", xt_hash);

		//verify funds have arrived
		let free = api.get_free_balance(&accountid);
		info!("TEE's NEW free balance = {:?}", free);

		api.signer = signer_orig;
	}
}
