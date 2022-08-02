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

#![cfg_attr(test, feature(assert_matches))]

use crate::{
	account_funding::{setup_account_funding, EnclaveAccountInfoProvider},
	error::Error,
	globals::tokio_handle::{GetTokioHandle, GlobalTokioHandle},
	initialized_service::{
		start_is_initialized_server, InitializationHandler, IsInitialized, TrackInitialization,
	},
	ocall_bridge::{
		bridge_api::Bridge as OCallBridge, component_factory::OCallBridgeComponentFactory,
	},
	parentchain_block_syncer::{ParentchainBlockSyncer, SyncParentchainBlocks},
	prometheus_metrics::{start_metrics_server, EnclaveMetricsReceiver, MetricsHandler},
	sync_block_gossiper::SyncBlockGossiper,
	utils::{check_files, extract_shard},
	worker::Worker,
	worker_peers_updater::WorkerPeersUpdater,
};
use base58::ToBase58;
use clap::{load_yaml, App};
use codec::{Decode, Encode};
use config::Config;
use enclave::{
	api::enclave_init,
	tls_ra::{enclave_request_state_provisioning, enclave_run_state_provisioning_server},
};
use futures::executor::block_on;
use itp_enclave_api::{
	direct_request::DirectRequest,
	enclave_base::EnclaveBase,
	remote_attestation::{RemoteAttestation, TlsRemoteAttestation},
	sidechain::Sidechain,
	teerex_api::TeerexApi,
	Enclave,
};
use itp_node_api_extensions::{
	node_api_factory::{CreateNodeApi, NodeApiFactory},
	AccountApi, ChainApi, PalletTeerexApi, ParentchainApi,
};
use itp_settings::{
	files::{SIDECHAIN_PURGE_INTERVAL, SIDECHAIN_PURGE_LIMIT, SIDECHAIN_STORAGE_PATH},
	sidechain::SLOT_DURATION,
};
use itp_types::light_client_init_params::LightClientInitParams;
use its_consensus_slots::start_slot_worker;
use its_peer_fetch::{
	block_fetch_client::BlockFetcher, untrusted_peer_fetch::UntrustedPeerFetcher,
};
use its_primitives::types::SignedBlock as SignedSidechainBlock;
use its_storage::{
	interface::FetchBlocks, start_sidechain_pruning_loop, BlockPruner, SidechainStorageLock,
};
use log::*;
use my_node_runtime::{Event, Hash, Header};
use sgx_types::*;
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_finality_grandpa::VersionedAuthorityList;
use sp_keyring::AccountKeyring;
use std::{
	path::PathBuf,
	str,
	sync::{
		mpsc::{channel, Sender},
		Arc,
	},
	thread,
	time::{Duration, Instant},
};
use substrate_api_client::{utils::FromHexString, Header as HeaderTrait, XtStatus};
use teerex_primitives::ShardIdentifier;

mod account_funding;
mod config;
mod enclave;
mod error;
mod globals;
mod initialized_service;
mod ocall_bridge;
mod parentchain_block_syncer;
mod prometheus_metrics;
mod setup;
mod sync_block_gossiper;
mod sync_state;
mod tests;
mod utils;
mod worker;
mod worker_peers_updater;

/// how many blocks will be synced before storing the chain db to disk
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub type EnclaveWorker = Worker<Config, NodeApiFactory, Enclave, InitializationHandler>;

fn main() {
	// Setup logging
	env_logger::init();

	let yml = load_yaml!("cli.yml");
	let matches = App::from_yaml(yml).get_matches();

	let config = Config::from(&matches);

	GlobalTokioHandle::initialize();

	// log this information, don't println because some python scripts for GA rely on the
	// stdout from the service
	#[cfg(feature = "production")]
	info!("*** Starting service in SGX production mode");
	#[cfg(not(feature = "production"))]
	info!("*** Starting service in SGX debug mode");

	let clean_reset = matches.is_present("clean-reset");
	if clean_reset {
		setup::purge_files_from_cwd().unwrap();
	}

	// build the entire dependency tree
	let tokio_handle = Arc::new(GlobalTokioHandle {});
	let sidechain_blockstorage = Arc::new(
		SidechainStorageLock::<SignedSidechainBlock>::new(PathBuf::from(&SIDECHAIN_STORAGE_PATH))
			.unwrap(),
	);
	let node_api_factory =
		Arc::new(NodeApiFactory::new(config.node_url(), AccountKeyring::Alice.pair()));
	let enclave = Arc::new(enclave_init(&config).unwrap());
	let initialization_handler = Arc::new(InitializationHandler::default());
	let worker = Arc::new(EnclaveWorker::new(
		config.clone(),
		enclave.clone(),
		node_api_factory.clone(),
		initialization_handler.clone(),
		Vec::new(),
	));
	let sync_block_gossiper =
		Arc::new(SyncBlockGossiper::new(tokio_handle.clone(), worker.clone()));
	let peer_updater = Arc::new(WorkerPeersUpdater::new(worker));
	let untrusted_peer_fetcher = UntrustedPeerFetcher::new(node_api_factory.clone());
	let peer_sidechain_block_fetcher =
		Arc::new(BlockFetcher::<SignedSidechainBlock, _>::new(untrusted_peer_fetcher));
	let enclave_metrics_receiver = Arc::new(EnclaveMetricsReceiver {});

	// initialize o-call bridge with a concrete factory implementation
	OCallBridge::initialize(Arc::new(OCallBridgeComponentFactory::new(
		node_api_factory.clone(),
		sync_block_gossiper,
		enclave.clone(),
		sidechain_blockstorage.clone(),
		peer_updater,
		peer_sidechain_block_fetcher,
		tokio_handle.clone(),
		enclave_metrics_receiver,
	)));

	if let Some(smatches) = matches.subcommand_matches("run") {
		let shard = extract_shard(smatches, enclave.as_ref());

		println!("Worker Config: {:?}", config);
		let skip_ra = smatches.is_present("skip-ra");
		let dev = smatches.is_present("dev");

		if clean_reset {
			setup::initialize_shard_and_keys(enclave.as_ref(), &shard).unwrap();
		}

		let node_api =
			node_api_factory.create_api().expect("Failed to create parentchain node API");

		let request_state = smatches.is_present("request-state");
		if request_state {
			sync_state::sync_state(&node_api, &shard, enclave.as_ref(), skip_ra);
		}

		start_worker(
			config,
			&shard,
			enclave,
			sidechain_blockstorage,
			skip_ra,
			dev,
			node_api,
			tokio_handle,
			initialization_handler,
		);
	} else if let Some(smatches) = matches.subcommand_matches("request-state") {
		println!("*** Requesting state from a registered worker \n");
		let node_api =
			node_api_factory.create_api().expect("Failed to create parentchain node API");
		sync_state::sync_state(
			&node_api,
			&extract_shard(smatches, enclave.as_ref()),
			enclave.as_ref(),
			smatches.is_present("skip-ra"),
		);
	} else if matches.is_present("shielding-key") {
		setup::generate_shielding_key_file(enclave.as_ref());
	} else if matches.is_present("signing-key") {
		setup::generate_signing_key_file(enclave.as_ref());
	} else if matches.is_present("dump-ra") {
		info!("*** Perform RA and dump cert to disk");
		enclave.dump_ra_to_disk().unwrap();
	} else if matches.is_present("mrenclave") {
		println!("{}", enclave.get_mrenclave().unwrap().encode().to_base58());
	} else if let Some(sub_matches) = matches.subcommand_matches("init-shard") {
		setup::init_shard(enclave.as_ref(), &extract_shard(sub_matches, enclave.as_ref()));
	} else if let Some(sub_matches) = matches.subcommand_matches("test") {
		if sub_matches.is_present("provisioning-server") {
			println!("*** Running Enclave MU-RA TLS server\n");
			enclave_run_state_provisioning_server(
				enclave.as_ref(),
				sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
				&config.mu_ra_url(),
				sub_matches.is_present("skip-ra"),
			);
			println!("[+] Done!");
		} else if sub_matches.is_present("provisioning-client") {
			println!("*** Running Enclave MU-RA TLS client\n");
			let shard = extract_shard(sub_matches, enclave.as_ref());
			enclave_request_state_provisioning(
				enclave.as_ref(),
				sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
				&config.mu_ra_url_external(),
				&shard,
				sub_matches.is_present("skip-ra"),
			)
			.unwrap();
			println!("[+] Done!");
		} else {
			tests::run_enclave_tests(sub_matches);
		}
	} else {
		println!("For options: use --help");
	}
}

/// FIXME: needs some discussion (restructuring?)
#[allow(clippy::too_many_arguments)]
fn start_worker<E, T, D, InitializationHandler>(
	config: Config,
	shard: &ShardIdentifier,
	enclave: Arc<E>,
	sidechain_storage: Arc<D>,
	skip_ra: bool,
	dev: bool,
	node_api: ParentchainApi,
	tokio_handle_getter: Arc<T>,
	initialization_handler: Arc<InitializationHandler>,
) where
	T: GetTokioHandle,
	E: EnclaveBase
		+ DirectRequest
		+ Sidechain
		+ RemoteAttestation
		+ TlsRemoteAttestation
		+ TeerexApi
		+ Clone,
	D: BlockPruner + FetchBlocks<SignedSidechainBlock> + Sync + Send + 'static,
	InitializationHandler: TrackInitialization + IsInitialized + Sync + Send + 'static,
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

	// ------------------------------------------------------------------------
	// let new workers call us for key provisioning
	println!("MU-RA server listening on {}", config.mu_ra_url());
	let ra_url = config.mu_ra_url();
	let enclave_api_key_prov = enclave.clone();
	thread::spawn(move || {
		enclave_run_state_provisioning_server(
			enclave_api_key_prov.as_ref(),
			sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
			&ra_url,
			skip_ra,
		)
	});

	let tokio_handle = tokio_handle_getter.get_handle();

	// ------------------------------------------------------------------------
	// Get the public key of our TEE.
	let genesis_hash = node_api.genesis_hash.as_bytes().to_vec();
	let tee_accountid = enclave_account(enclave.as_ref());

	// ------------------------------------------------------------------------
	// Start `is_initialized` server.
	let untrusted_http_server_port = config
		.try_parse_untrusted_http_server_port()
		.expect("untrusted http server port to be a valid port number");
	let initialization_handler_clone = initialization_handler.clone();
	tokio_handle.spawn(async move {
		if let Err(e) =
			start_is_initialized_server(initialization_handler_clone, untrusted_http_server_port)
				.await
		{
			error!("Unexpected error in `is_initialized` server: {:?}", e);
		}
	});

	// ------------------------------------------------------------------------
	// Start prometheus metrics server.
	if config.enable_metrics_server {
		let enclave_wallet =
			Arc::new(EnclaveAccountInfoProvider::new(node_api.clone(), tee_accountid.clone()));
		let metrics_handler = Arc::new(MetricsHandler::new(enclave_wallet));
		let metrics_server_port = config
			.try_parse_metrics_server_port()
			.expect("metrics server port to be a valid port number");
		tokio_handle.spawn(async move {
			if let Err(e) = start_metrics_server(metrics_handler, metrics_server_port).await {
				error!("Unexpected error in Prometheus metrics server: {:?}", e);
			}
		});
	}

	// ------------------------------------------------------------------------
	// Start trusted worker rpc server
	let direct_invocation_server_addr = config.trusted_worker_url_internal();
	let enclave_for_direct_invocation = enclave.clone();
	thread::spawn(move || {
		println!(
			"[+] Trusted RPC direct invocation server listening on {}",
			direct_invocation_server_addr
		);
		enclave_for_direct_invocation
			.init_direct_invocation_server(direct_invocation_server_addr)
			.unwrap();
		println!("[+] RPC direct invocation server shut down");
	});

	// ------------------------------------------------------------------------
	// Start untrusted worker rpc server.
	// FIXME: this should be removed - this server should only handle untrusted things.
	// i.e move sidechain block importing to trusted worker.
	let enclave_for_block_gossip_rpc_server = enclave.clone();
	let untrusted_url = config.untrusted_worker_url();
	println!("[+] Untrusted RPC server listening on {}", &untrusted_url);
	let sidechain_storage_for_rpc = sidechain_storage.clone();
	let _untrusted_rpc_join_handle = tokio_handle.spawn(async move {
		itc_rpc_server::run_server(
			&untrusted_url,
			enclave_for_block_gossip_rpc_server,
			sidechain_storage_for_rpc,
		)
		.await
		.unwrap();
	});

	// ------------------------------------------------------------------------
	// Perform a remote attestation and get an unchecked extrinsic back.
	let nonce = node_api.get_nonce_of(&tee_accountid).unwrap();
	info!("Enclave nonce = {:?}", nonce);
	enclave
		.set_nonce(nonce)
		.expect("Could not set nonce of enclave. Returning here...");
	let trusted_url = config.trusted_worker_url_external();
	let uxt = if skip_ra {
		println!(
			"[!] skipping remote attestation. Registering enclave without attestation report."
		);
		enclave.mock_register_xt(node_api.genesis_hash, nonce, &trusted_url).unwrap()
	} else {
		enclave
			.perform_ra(genesis_hash, nonce, trusted_url.as_bytes().to_vec())
			.unwrap()
	};

	let mut xthex = hex::encode(uxt);
	xthex.insert_str(0, "0x");

	// Account funds
	if let Err(x) = setup_account_funding(&node_api, &tee_accountid, xthex.clone(), dev) {
		error!("Starting worker failed: {:?}", x);
		// Return without registering the enclave. This will fail and the transaction will be banned for 30min.
		return
	}

	println!("[>] Register the enclave (send the extrinsic)");
	let register_enclave_xt_hash = node_api.send_extrinsic(xthex, XtStatus::Finalized).unwrap();
	println!("[<] Extrinsic got finalized. Hash: {:?}\n", register_enclave_xt_hash);

	let register_enclave_xt_header =
		node_api.get_header(register_enclave_xt_hash).unwrap().unwrap();
	let we_are_primary_validateer =
		we_are_primary_validateer(&node_api, &register_enclave_xt_header).unwrap();

	if we_are_primary_validateer {
		println!("[+] We are the primary validateer");
	} else {
		println!("[+] We are NOT the primary validateer");
	}

	initialization_handler.registered_on_parentchain();

	let last_synced_header = init_light_client(&node_api, enclave.clone()).unwrap();
	println!("*** [+] Finished syncing light client, syncing parentchain...");

	// Syncing all parentchain blocks, this might take a while..
	let parentchain_block_syncer =
		Arc::new(ParentchainBlockSyncer::new(node_api.clone(), enclave.clone()));
	let mut last_synced_header = parentchain_block_syncer.sync_parentchain(last_synced_header);

	// If we're the first validateer to register, also trigger parentchain block import.
	if we_are_primary_validateer {
		last_synced_header = import_parentchain_blocks_until_self_registry(
			enclave.clone(),
			parentchain_block_syncer,
			&last_synced_header,
			&register_enclave_xt_header,
		)
		.unwrap();
	}

	// ------------------------------------------------------------------------
	// Initialize sidechain components (has to be AFTER init_light_client()
	enclave.init_enclave_sidechain_components().unwrap();

	// ------------------------------------------------------------------------
	// Start interval sidechain block production (execution of trusted calls, sidechain block production).
	let sidechain_enclave_api = enclave.clone();
	println!("[+] Spawning thread for sidechain block production");
	thread::Builder::new()
		.name("interval_block_production_timer".to_owned())
		.spawn(move || {
			let future = start_slot_worker(
				|| execute_trusted_calls(sidechain_enclave_api.as_ref()),
				SLOT_DURATION,
			);
			block_on(future);
			println!("[!] Sidechain block production loop has terminated");
		})
		.unwrap();

	// ------------------------------------------------------------------------
	// start parentchain syncing loop (subscribe to header updates)
	let api4 = node_api.clone();
	let parentchain_sync_enclave_api = enclave.clone();
	thread::Builder::new()
		.name("parentchain_sync_loop".to_owned())
		.spawn(move || {
			if let Err(e) = subscribe_to_parentchain_new_headers(
				parentchain_sync_enclave_api,
				&api4,
				last_synced_header,
			) {
				error!("Parentchain block syncing terminated with a failure: {:?}", e);
			}
			println!("[!] Parentchain block syncing has terminated");
		})
		.unwrap();

	//-------------------------------------------------------------------------
	// start execution of trusted getters
	let trusted_getters_enclave_api = enclave;
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
	spawn_worker_for_shard_polling(shard, node_api.clone(), initialization_handler);

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

/// Start polling loop to wait until we have a worker for a shard registered on
/// the parentchain (TEEREX WorkerForShard). This is the pre-requisite to be
/// considered initialized and ready for the next worker to start.
fn spawn_worker_for_shard_polling<InitializationHandler>(
	shard: &ShardIdentifier,
	node_api: ParentchainApi,
	initialization_handler: Arc<InitializationHandler>,
) where
	InitializationHandler: TrackInitialization + Sync + Send + 'static,
{
	let shard_for_initialized = *shard;
	thread::spawn(move || {
		const POLL_INTERVAL_SECS: u64 = 2;

		loop {
			info!("Polling for worker for shard ({} seconds interval)", POLL_INTERVAL_SECS);
			if let Ok(Some(_)) = node_api.worker_for_shard(&shard_for_initialized, None) {
				// Set that the service is initialized.
				initialization_handler.worker_for_shard_registered();
				println!("[+] Found `WorkerForShard` on parentchain state");
				break
			}
			thread::sleep(Duration::from_secs(POLL_INTERVAL_SECS));
		}
	});
}

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
					my_node_runtime::pallet_teerex::Event::AddedEnclave(sender, worker_url) => {
						println!("[+] Received AddedEnclave event");
						println!("    Sender (Worker):  {:?}", sender);
						println!("    Registered URL: {:?}", str::from_utf8(worker_url).unwrap());
					},
					my_node_runtime::pallet_teerex::Event::Forwarded(shard) => {
						println!(
							"[+] Received trusted call for shard {}",
							shard.encode().to_base58()
						);
					},
					my_node_runtime::pallet_teerex::Event::ProcessedParentchainBlock(
						sender,
						block_hash,
						merkle_root,
					) => {
						info!("[+] Received ProcessedParentchainBlock event");
						debug!("    From:    {:?}", sender);
						debug!("    Block Hash: {:?}", hex::encode(block_hash));
						debug!("    Merkle Root: {:?}", hex::encode(merkle_root));
					},
					my_node_runtime::pallet_teerex::Event::ShieldFunds(incognito_account) => {
						info!("[+] Received ShieldFunds event");
						debug!("    For:    {:?}", incognito_account);
					},
					my_node_runtime::pallet_teerex::Event::UnshieldedFunds(incognito_account) => {
						info!("[+] Received UnshieldedFunds event");
						debug!("    For:    {:?}", incognito_account);
					},
					_ => {
						trace!("Ignoring unsupported pallet_teerex event");
					},
				}
			},
			Event::Sidechain(re) => match &re {
				my_node_runtime::pallet_sidechain::Event::ProposedSidechainBlock(
					sender,
					payload,
				) => {
					info!("[+] Received ProposedSidechainBlock event");
					debug!("    From:    {:?}", sender);
					debug!("    Payload: {:?}", hex::encode(payload));
				},
				_ => {
					trace!("Ignoring unsupported pallet_sidechain event");
				},
			},
			_ => {
				trace!("Ignoring event {:?}", evr);
			},
		}
	}
}

pub fn init_light_client<E: EnclaveBase + Sidechain>(
	api: &ParentchainApi,
	enclave_api: Arc<E>,
) -> Result<Header, Error> {
	let genesis_hash = api.get_genesis_hash().unwrap();
	let genesis_header: Header = api.get_header(Some(genesis_hash)).unwrap().unwrap();
	info!("Got genesis Header: \n {:?} \n", genesis_header);
	if api.is_grandpa_available()? {
		let grandpas = api.grandpa_authorities(Some(genesis_hash)).unwrap();
		let grandpa_proof = api.grandpa_authorities_proof(Some(genesis_hash)).unwrap();

		debug!("Grandpa Authority List: \n {:?} \n ", grandpas);

		let authority_list = VersionedAuthorityList::from(grandpas);

		let params = LightClientInitParams::Grandpa {
			genesis_header,
			authorities: authority_list.into(),
			authority_proof: grandpa_proof,
		};

		Ok(enclave_api.init_light_client(params).unwrap())
	} else {
		let params = LightClientInitParams::Parachain { genesis_header };

		Ok(enclave_api.init_light_client(params).unwrap())
	}
}

/// Subscribe to the node API finalized heads stream and trigger a parent chain sync
/// upon receiving a new header.
fn subscribe_to_parentchain_new_headers<E: EnclaveBase + Sidechain>(
	enclave_api: Arc<E>,
	api: &ParentchainApi,
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

/// Get the public signing key of the TEE.
fn enclave_account<E: EnclaveBase>(enclave_api: &E) -> AccountId32 {
	let tee_public = enclave_api.get_ecc_signing_pubkey().unwrap();
	trace!("[+] Got ed25519 account of TEE = {}", tee_public.to_ss58check());
	AccountId32::from(*tee_public.as_array_ref())
}

/// Ensure we're synced up until the parentchain block where we have registered ourselves.
fn import_parentchain_blocks_until_self_registry<
	E: EnclaveBase + TeerexApi + Sidechain,
	ParentchainSyncer: SyncParentchainBlocks,
>(
	enclave_api: Arc<E>,
	parentchain_block_syncer: Arc<ParentchainSyncer>,
	last_synced_header: &Header,
	register_enclave_xt_header: &Header,
) -> Result<Header, Error> {
	info!(
		"We're the first validateer to be registered, syncing parentchain blocks until the one we have registered ourselves on."
	);
	let mut last_synced_header = last_synced_header.clone();

	while last_synced_header.number() < register_enclave_xt_header.number() {
		last_synced_header = parentchain_block_syncer.sync_parentchain(last_synced_header);
	}
	enclave_api.trigger_parentchain_block_import()?;

	Ok(last_synced_header)
}

/// Checks if we are the first validateer to register on the parentchain.
fn we_are_primary_validateer(
	node_api: &ParentchainApi,
	register_enclave_xt_header: &Header,
) -> Result<bool, Error> {
	let enclave_count_of_previous_block =
		node_api.enclave_count(Some(*register_enclave_xt_header.parent_hash()))?;
	Ok(enclave_count_of_previous_block == 0)
}
