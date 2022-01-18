/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

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
	error::Error,
	globals::{
		tokio_handle::{GetTokioHandle, GlobalTokioHandle},
		worker::{GlobalWorker, Worker},
	},
	node_api_factory::{CreateNodeApi, GlobalUrlNodeApiFactory},
	ocall_bridge::{
		bridge_api::Bridge as OCallBridge, component_factory::OCallBridgeComponentFactory,
	},
	parentchain_block_syncer::ParentchainBlockSyncer,
	sync_block_gossiper::SyncBlockGossiper,
	utils::{check_files, extract_shard},
	worker::worker_url_into_async_rpc_url,
};
use base58::ToBase58;
use clap::{load_yaml, App};
use codec::Encode;
use config::Config;
use enclave::{
	api::enclave_init,
	tls_ra::{enclave_request_key_provisioning, enclave_run_key_provisioning_server},
};
use itc_rpc_client::direct_client::DirectClient;
use itp_api_client_extensions::{AccountApi, ChainApi};
use itp_enclave_api::{
	direct_request::DirectRequest,
	enclave_base::EnclaveBase,
	remote_attestation::{RemoteAttestation, TlsRemoteAttestation},
	sidechain::Sidechain,
	teeracle_api::TeeracleApi,
	teerex_api::TeerexApi,
};
use itp_settings::{
	files::{
		ENCRYPTED_STATE_FILE, SHARDS_PATH, SHIELDING_KEY_FILE, SIDECHAIN_STORAGE_PATH,
		SIGNING_KEY_FILE,
	},
	node::MARKET_DATA_UPDATE_INTERVAL,
	worker::{EXISTENTIAL_DEPOSIT_FACTOR_FOR_INIT_FUNDS, REGISTERING_FEE_FACTOR_FOR_INIT_FUNDS},
};
use its_primitives::types::SignedBlock as SignedSidechainBlock;
use its_storage::{BlockPruner, SidechainStorageLock};
use log::*;
use my_node_runtime::Header;
use parse_duration::parse;
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
	path::{Path, PathBuf},
	str,
	sync::Arc,
	thread,
	time::{Duration, Instant},
};
use substrate_api_client::{rpc::WsRpcClient, Api, GenericAddress, XtStatus};
use teerex_primitives::ShardIdentifier;

mod config;
mod enclave;
mod error;
mod globals;
mod node_api_factory;
mod ocall_bridge;
mod parentchain_block_syncer;
mod sync_block_gossiper;
mod tests;
mod utils;
mod worker;

/// how many blocks will be synced before storing the chain db to disk
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
	// Setup logging
	env_logger::init();

	let yml = load_yaml!("cli.yml");
	let matches = App::from_yaml(yml).get_matches();

	let mut config = Config::from(&matches);

	GlobalTokioHandle::initialize();

	// log this information, don't println because some python scripts for GA rely on the
	// stdout from the service
	#[cfg(feature = "production")]
	info!("*** Starting service in SGX production mode");
	#[cfg(not(feature = "production"))]
	info!("*** Starting service in SGX debug mode");

	// build the entire dependency tree
	let worker = Arc::new(GlobalWorker {});
	let tokio_handle = Arc::new(GlobalTokioHandle {});
	let sync_block_gossiper = Arc::new(SyncBlockGossiper::new(tokio_handle.clone(), worker));
	let sidechain_blockstorage = Arc::new(
		SidechainStorageLock::<SignedSidechainBlock>::new(PathBuf::from(&SIDECHAIN_STORAGE_PATH))
			.unwrap(),
	);
	let node_api_factory = Arc::new(GlobalUrlNodeApiFactory::new(config.node_url()));
	let enclave = Arc::new(enclave_init().unwrap());

	// initialize o-call bridge with a concrete factory implementation
	OCallBridge::initialize(Arc::new(OCallBridgeComponentFactory::new(
		node_api_factory.clone(),
		sync_block_gossiper,
		enclave.clone(),
		sidechain_blockstorage.clone(),
	)));

	if let Some(smatches) = matches.subcommand_matches("run") {
		let shard = extract_shard(smatches, enclave.as_ref());

		// Todo: Is this deprecated?? It is only used in remote attestation.
		config.set_ext_api_url(
			smatches
				.value_of("w-server")
				.map(ToString::to_string)
				.unwrap_or_else(|| format!("ws://127.0.0.1:{}", config.worker_rpc_port)),
		);

		println!("Worker Config: {:?}", config);
		let skip_ra = smatches.is_present("skip-ra");
		let dev = smatches.is_present("dev");

		let interval = smatches
			.value_of("interval")
			.map_or_else(|| Ok(MARKET_DATA_UPDATE_INTERVAL), parse)
			.unwrap_or_else(|e| panic!("Interval parsing error {:?}", e));

		println!("Update exchange rate interval is {:?}", interval);

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
			sidechain_blockstorage,
			skip_ra,
			dev,
			interval,
			node_api,
			tokio_handle,
		);
	} else if let Some(smatches) = matches.subcommand_matches("request-keys") {
		let shard = extract_shard(smatches, enclave.as_ref());
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
		let shard = extract_shard(_matches, enclave.as_ref());
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
			tests::run_enclave_tests(_matches);
		}
	} else {
		println!("For options: use --help");
	}
}

/// FIXME: needs some discussion (restructuring?)
#[allow(clippy::too_many_arguments)]
fn start_worker<E, T, D>(
	config: Config,
	shard: &ShardIdentifier,
	enclave: Arc<E>,
	_sidechain_storage: Arc<D>,
	skip_ra: bool,
	dev: bool,
	interval: Duration,
	mut node_api: Api<sr25519::Pair, WsRpcClient>,
	tokio_handle: Arc<T>,
) where
	T: GetTokioHandle,
	E: EnclaveBase
		+ DirectRequest
		+ Sidechain
		+ RemoteAttestation
		+ TlsRemoteAttestation
		+ TeerexApi
		+ TeeracleApi
		+ Clone,
	D: BlockPruner + Sync + Send + 'static,
{
	println!("IntegriTEE Worker v{}", VERSION);
	info!("starting worker on shard {}", shard.encode().to_base58());
	// ------------------------------------------------------------------------
	// check for required files
	check_files();
	// ------------------------------------------------------------------------
	// initialize the enclave
	let mrenclave = enclave.get_mrenclave().unwrap();
	println!("MRENCLAVE={}", mrenclave.to_base58());
	println!("MRENCLAVE in hex {:?}", hex::encode(mrenclave));

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
	let direct_invocation_server_addr = config.worker_url();
	let enclave_for_direct_invocation = enclave.clone();
	thread::spawn(move || {
		println!(
			"[+] RPC direction invocation server listening on wss://{}",
			direct_invocation_server_addr
		);
		enclave_for_direct_invocation
			.init_direct_invocation_server(direct_invocation_server_addr)
			.unwrap();
		println!("[+] RPC direction invocation server shut down");
	});

	// listen for sidechain_block import request. Later the `start_worker_api_direct_server`
	// should be merged into this one.
	let url = worker_url_into_async_rpc_url(&config.worker_url()).unwrap();

	let handle = tokio_handle.get_handle();
	let enclave_for_block_gossip_rpc_server = enclave.clone();
	handle.spawn(async move {
		itc_rpc_server::run_server(&url, enclave_for_block_gossip_rpc_server)
			.await
			.unwrap()
	});
	// ------------------------------------------------------------------------
	// start the substrate-api-client to communicate with the node
	let genesis_hash = node_api.genesis_hash.as_bytes().to_vec();

	let tee_accountid = enclave_account(enclave.as_ref());
	println!("MRENCLAVE account {:} ", &tee_accountid.to_ss58check());
	// ------------------------------------------------------------------------
	// perform a remote attestation and get an unchecked extrinsic back

	// get enclaves's account nonce
	let nonce = node_api.get_nonce_of(&tee_accountid).unwrap();
	info!("Enclave nonce = {:?}", nonce);
	enclave
		.set_nonce(nonce)
		.expect("Could not set nonce of enclave. Returning here...");

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

	// Account funds
	if let Err(x) = account_funding(&mut node_api, &tee_accountid, xthex.clone(), dev) {
		error!("Starting worker failed: {:?}", x);
		// Return without registering the enclave. This will fail and the transaction will be banned for 30min.
		return
	}

	// send the extrinsic and wait for confirmation
	println!("[>] Register the enclave (send the extrinsic)");
	let tx_hash = node_api.send_extrinsic(xthex, XtStatus::Finalized).unwrap();
	println!("[<] Extrinsic got finalized. Hash: {:?}\n", tx_hash);

	// start update exchange rate loop
	let api5 = node_api.clone();
	let market_enclave_api = enclave;
	start_interval_market_update(&api5, interval, market_enclave_api.as_ref());

	/*
	   let last_synced_header = init_light_client(&node_api, enclave.clone()).unwrap();
	   println!("*** [+] Finished syncing light client\n");

	   // ------------------------------------------------------------------------
	   // start interval block production (execution of trusted calls, sidechain block production)
	   let side_chain_enclave_api = enclave.clone();
	   thread::Builder::new()
		   .name("interval_block_production_timer".to_owned())
		   .spawn(move || {
			   let future = start_slot_worker(
				   || execute_trusted_calls(side_chain_enclave_api.as_ref()),
				   SLOT_DURATION,
			   );
			   block_on(future);
		   })
		   .unwrap();

	   // ------------------------------------------------------------------------
	   // start parentchain syncing loop (subscribe to header updates)
	   let api4 = node_api.clone();
	   let parentchain_sync_enclave_api = enclave.clone();
	   thread::Builder::new()
		   .name("parent_chain_sync_loop".to_owned())
		   .spawn(move || {
			   if let Err(e) = subscribe_to_parentchain_new_headers(
				   parentchain_sync_enclave_api,
				   &api4,
				   last_synced_header,
			   ) {
				   error!("Parentchain block syncing terminated with a failure: {:?}", e);
			   }
			   println!("[+] Parentchain block syncing has terminated");
		   })
		   .unwrap();

	   //-------------------------------------------------------------------------
	   // start execution of trusted getters
	   let trusted_getters_enclave_api = enclave.clone();
	   thread::Builder::new()
		   .name("trusted_getters_execution".to_owned())
		   .spawn(move || {
			   start_interval_trusted_getter_execution(trusted_getters_enclave_api.as_ref())
		   })
		   .unwrap();

	   // ------------------------------------------------------------------------
	   // start sidechain pruning loop
	   thread::Builder::new()
		   .name("sidechain_pruning_loop".to_owned())
		   .spawn(move || {
			   start_sidechain_pruning_loop(
				   &sidechain_storage,
				   SIDECHAIN_PURGE_INTERVAL,
				   SIDECHAIN_PURGE_LIMIT,
			   );
		   })
		   .unwrap();

	   // ------------------------------------------------------------------------
	   // start update exchange rate loop
	   let api5 = node_api.clone();
	   let market_enclave_api = enclave;
	   thread::Builder::new()
		   .name("update_market_data".to_owned())
		   .spawn(move || {
			   start_interval_market_update(&api5, interval, market_enclave_api.as_ref());
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
	*/
}

/*
/// Starts the execution of trusted getters in repeating intervals.
///
/// The getters are executed in a pre-defined slot duration.
fn start_interval_trusted_getter_execution<E: Sidechain>(enclave_api: &E) {
	use itp_settings::enclave::TRUSTED_GETTERS_SLOT_DURATION;

	schedule_on_repeating_intervals(
		|| {
			if let Err(e) = enclave_api.execute_trusted_getters() {
				error!("Execution of trusted getters failed: {:?}", e);
			}
		},
		TRUSTED_GETTERS_SLOT_DURATION,
	);
}
*/
/// Send extrinsic to chain according to the market data update interval in the settings
/// with the current market data (for now only exchange rate).
fn start_interval_market_update<E: EnclaveBase + TeeracleApi>(
	api: &Api<sr25519::Pair, WsRpcClient>,
	interval: Duration,
	enclave_api: &E,
) {
	schedule_on_repeating_intervals(
		|| {
			execute_update_market(api, enclave_api);
		},
		interval,
	);
}

fn execute_update_market<E: EnclaveBase + TeeracleApi>(
	node_api: &Api<sr25519::Pair, WsRpcClient>,
	enclave: &E,
) {
	// Get market data for usd (hardcoded)
	let updated_extrinsic =
		match enclave.update_market_data_xt(node_api.genesis_hash, "TEER", "USD") {
			Err(e) => {
				error!("{:?}", e);
				return
			},
			Ok(r) => r,
		};

	let mut hex_encoded_extrinsic = hex::encode(updated_extrinsic);
	hex_encoded_extrinsic.insert_str(0, "0x");

	// Send the extrinsic to the parentchain and wait for InBlock confirmation.
	println!("[>] Update the exchange rate (send the extrinsic)");
	let extrinsic_hash = match node_api.send_extrinsic(hex_encoded_extrinsic, XtStatus::InBlock) {
		Err(e) => {
			error!("{:?}: ", e);
			return
		},
		Ok(r) => r,
	};
	println!("[<] Extrinsic got included into a block. Hash: {:?}\n", extrinsic_hash);
}

/// Schedules a task on perpetually looping intervals.
///
/// In case the task takes longer than is scheduled by the interval duration,
/// the interval timing will drift. The task is responsible for
/// ensuring it does not use up more time than is scheduled.
fn schedule_on_repeating_intervals<T>(task: T, interval_duration: Duration)
where
	T: Fn(),
{
	let mut interval_start = Instant::now();
	loop {
		let elapsed = interval_start.elapsed();

		if elapsed >= interval_duration {
			// update interval time
			interval_start = Instant::now();
			task();
		} else {
			// sleep for the rest of the interval
			let sleep_time = interval_duration - elapsed;
			thread::sleep(sleep_time);
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
		provider_url,
		skip_ra,
	)
	.unwrap();
	println!("key provisioning successfully performed");
}

/*
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
					pallet_balances::Event::Transfer {
						from: transactor,
						to: dest,
						amount: value,
					} => {
						debug!("    Transactor:  {:?}", transactor.to_ss58check());
						debug!("    Destination: {:?}", dest.to_ss58check());
						debug!("    Value:       {:?}", value);
					},
					_ => {
						trace!("Ignoring unsupported balances event");
					},
				}
			},
			Event::Teerex(re) => {
				debug!("{:?}", re);
				match &re {
					my_node_runtime::pallet_teerex::RawEvent::AddedEnclave(sender, worker_url) => {
						println!("[+] Received AddedEnclave event");
						println!("    Sender (Worker):  {:?}", sender);
						println!("    Registered URL: {:?}", str::from_utf8(worker_url).unwrap());
					},
					my_node_runtime::pallet_teerex::RawEvent::Forwarded(shard) => {
						println!(
							"[+] Received trusted call for shard {}",
							shard.encode().to_base58()
						);
					},
					my_node_runtime::pallet_teerex::RawEvent::ProcessedParentchainBlock(
						sender,
						block_hash,
						merkle_root,
					) => {
						info!("[+] Received ProcessedParentchainBlock event");
						debug!("    From:    {:?}", sender);
						debug!("    Block Hash: {:?}", hex::encode(block_hash));
						debug!("    Merkle Root: {:?}", hex::encode(merkle_root));
					},
					my_node_runtime::pallet_teerex::RawEvent::ProposedSidechainBlock(
						sender,
						payload,
					) => {
						info!("[+] Received ProposedSidechainBlock event");
						debug!("    From:    {:?}", sender);
						debug!("    Payload: {:?}", hex::encode(payload));
					},
					my_node_runtime::pallet_teerex::RawEvent::ShieldFunds(incognito_account) => {
						info!("[+] Received ShieldFunds event");
						debug!("    For:    {:?}", incognito_account);
					},
					my_node_runtime::pallet_teerex::RawEvent::UnshieldedFunds(
						incognito_account,
					) => {
						info!("[+] Received UnshieldedFunds event");
						debug!("    For:    {:?}", incognito_account);
					},
					_ => {
						trace!("Ignoring unsupported pallet_teerex event");
					},
				}
			},
			/*
			/// FIXME: to add as soon as worker, node, and pallet are compatible (based on the same substrate version)
						Event::Teeracle(re) => {
							debug!("{:?}", re);
							match &re {
								my_node_runtime::pallet_teeracle::RawEvent::ExchangeRateUpdated(
									currency,
									new_value,
								) => {
									println!("[+] Received ExchangeRateUpdated event");
									println!("    Currency:  {:?}", str::from_utf8(&currency).unwrap());
									println!("    Exchange rate: {}", new_value.to_string());
								},
							}
						},
			*/
			_ => {
				trace!("Ignoring event {:?}", evr);
			},
		}
	}
}
*/

pub fn init_light_client<E: EnclaveBase + Sidechain>(
	api: &Api<sr25519::Pair, WsRpcClient>,
	enclave_api: Arc<E>,
) -> Result<Header, Error> {
	let genesis_hash = api.get_genesis_hash().unwrap();
	let genesis_header: Header = api.get_header(Some(genesis_hash)).unwrap().unwrap();
	info!("Got genesis Header: \n {:?} \n", genesis_header);
	let grandpas = api.grandpa_authorities(Some(genesis_hash)).unwrap();
	let grandpa_proof = api.grandpa_authorities_proof(Some(genesis_hash)).unwrap();

	debug!("Grandpa Authority List: \n {:?} \n ", grandpas);

	let authority_list = VersionedAuthorityList::from(grandpas);

	let latest = enclave_api
		.init_light_client(genesis_header, authority_list, grandpa_proof)
		.unwrap();

	info!("Finished initializing light client, syncing parent chain...");

	let parentchain_block_syncer = ParentchainBlockSyncer::new(api.clone(), enclave_api.clone());
	let latest_synced_header = parentchain_block_syncer.sync_parentchain(latest);

	enclave_api.trigger_parentchain_block_import().map_err(Error::EnclaveApi)?;

	Ok(latest_synced_header)
}

/*
/// Subscribe to the node API finalized heads stream and trigger a parent chain sync
/// upon receiving a new header.
fn subscribe_to_parentchain_new_headers<E: EnclaveBase + Sidechain>(
	enclave_api: Arc<E>,
	api: &Api<sr25519::Pair, WsRpcClient>,
	mut last_synced_header: Header,
) -> Result<(), Error> {
	let (sender, receiver) = channel();
	api.subscribe_finalized_heads(sender).map_err(Error::ApiClient)?;

	let parentchain_block_syncer = ParentchainBlockSyncer::new(api.clone(), enclave_api);
	loop {
		let new_header: Header = match receiver.recv() {
			Ok(header_str) => serde_json::from_str(&header_str).map_err(Error::Serialization),
			Err(e) => Err(Error::ApiSubscriptionDisconnected(e)),
		}?;

		println!(
			"[+] Received finalized header update ({}), syncing parent chain...",
			new_header.number
		);

		last_synced_header = parentchain_block_syncer.sync_parentchain(last_synced_header);
	}
}

/// Execute trusted operations in the enclave
///
///
fn execute_trusted_calls<E: Sidechain>(enclave_api: &E) {
	if let Err(e) = enclave_api.execute_trusted_calls() {
		error!("{:?}", e);
	};
}
*/

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

fn account_funding(
	api: &mut Api<sr25519::Pair, WsRpcClient>,
	accountid: &AccountId32,
	extrinsic_prefix: String,
	dev: bool,
) -> Result<(), Error> {
	// Account funds
	if dev {
		// Development mode, the faucet will ensure that the enclave has enough funds
		ensure_account_has_funds(api, accountid)?;
	} else {
		// Production mode, there is no faucet.
		let registration_fees = enclave_registration_fees(api, &extrinsic_prefix)?;
		info!("Registration fees = {:?}", registration_fees);
		let free_balance = api.get_free_balance(accountid)?;
		info!("TEE's free balance = {:?}", free_balance);

		let min_required_funds =
			registration_fees.saturating_mul(REGISTERING_FEE_FACTOR_FOR_INIT_FUNDS);
		let missing_funds = min_required_funds.saturating_sub(free_balance);

		if missing_funds > 0 {
			// If there are not enough funds, then the user can send the missing TEER to the enclave address and start again.
			println!(
				"Enclave account: {:}, missing funds {}",
				accountid.to_ss58check(),
				missing_funds
			);
			return Err(Error::Custom(
				"Enclave does not have enough funds on the parentchain to register.".into(),
			))
		}
	}
	Ok(())
}
// Alice plays the faucet and sends some funds to the account if balance is low
fn ensure_account_has_funds(
	api: &mut Api<sr25519::Pair, WsRpcClient>,
	accountid: &AccountId32,
) -> Result<(), Error> {
	// check account balance
	let free_balance = api.get_free_balance(accountid)?;
	info!("TEE's free balance = {:?}", free_balance);

	let existential_deposit = api.get_existential_deposit()?;
	info!("Existential deposit is = {:?}", existential_deposit);

	let min_required_funds =
		existential_deposit.saturating_mul(EXISTENTIAL_DEPOSIT_FACTOR_FOR_INIT_FUNDS);
	let missing_funds = min_required_funds.saturating_sub(free_balance);

	if missing_funds > 0 {
		bootstrap_funds_from_alice(api, accountid, missing_funds)?;
	}
	Ok(())
}

fn enclave_registration_fees(
	api: &mut Api<sr25519::Pair, WsRpcClient>,
	xthex_prefixed: &str,
) -> Result<u128, Error> {
	let reg_fee_details = api.get_fee_details(xthex_prefixed, None)?;
	match reg_fee_details {
		Some(details) => match details.inclusion_fee {
			Some(fee) => Ok(fee.inclusion_fee()),
			None => Err(Error::Custom(
				"Inclusion fee for the registration of the enclave is None!".into(),
			)),
		},
		None =>
			Err(Error::Custom("Fee Details for the registration of the enclave is None !".into())),
	}
}

// Alice sends some funds to the account
fn bootstrap_funds_from_alice(
	api: &mut Api<sr25519::Pair, WsRpcClient>,
	accountid: &AccountId32,
	funding_amount: u128,
) -> Result<(), Error> {
	let alice = AccountKeyring::Alice.pair();
	info!("encoding Alice's public 	= {:?}", alice.public().0.encode());
	let alice_acc = AccountId32::from(*alice.public().as_array_ref());
	info!("encoding Alice's AccountId = {:?}", alice_acc.encode());

	let alice_free = api.get_free_balance(&alice_acc)?;
	info!("    Alice's free balance = {:?}", alice_free);
	let nonce = api.get_nonce_of(&alice_acc)?;
	info!("    Alice's Account Nonce is {}", nonce);

	if funding_amount > alice_free {
		println!(
			"funding amount is to high: please change MIN_FUND_INCREASE_FACTOR ({:?})",
			funding_amount
		);
		return Err(Error::ApplicationSetup)
	}

	let signer_orig = api.signer.clone();
	api.signer = Some(alice);

	println!("[+] bootstrap funding Enclave from Alice's funds");
	let xt = api.balance_transfer(GenericAddress::Id(accountid.clone()), funding_amount);
	let xt_hash = api.send_extrinsic(xt.hex_encode(), XtStatus::InBlock)?;
	info!("[<] Extrinsic got included in a block. Hash: {:?}\n", xt_hash);

	// Verify funds have arrived.
	let free_balance = api.get_free_balance(accountid);
	info!("TEE's NEW free balance = {:?}", free_balance);

	api.signer = signer_orig;
	Ok(())
}
