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

#[cfg(feature = "teeracle")]
use crate::teeracle::start_interval_market_update;

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
	parentchain_handler::{HandleParentchain, ParentchainHandler},
	prometheus_metrics::{start_metrics_server, EnclaveMetricsReceiver, MetricsHandler},
	sidechain_setup::{sidechain_init_block_production, sidechain_start_untrusted_rpc_server},
	sync_block_broadcaster::SyncBlockBroadcaster,
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
use itp_enclave_api::{
	direct_request::DirectRequest,
	enclave_base::EnclaveBase,
	remote_attestation::{RemoteAttestation, TlsRemoteAttestation},
	sidechain::Sidechain,
	teeracle_api::TeeracleApi,
	Enclave,
};
use itp_node_api::{
	api_client::{AccountApi, PalletTeerexApi, ParentchainApi},
	metadata::NodeMetadata,
	node_api_factory::{CreateNodeApi, NodeApiFactory},
};
use itp_settings::{
	files::SIDECHAIN_STORAGE_PATH,
	worker_mode::{ProvideWorkerMode, WorkerMode, WorkerModeProvider},
};
use its_peer_fetch::{
	block_fetch_client::BlockFetcher, untrusted_peer_fetch::UntrustedPeerFetcher,
};
use its_primitives::types::block::SignedBlock as SignedSidechainBlock;
use its_storage::{interface::FetchBlocks, BlockPruner, SidechainStorageLock};
use log::*;
use my_node_runtime::{Hash, Header, RuntimeEvent};
use sgx_types::*;
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_keyring::AccountKeyring;
use std::{
	path::PathBuf,
	str,
	sync::{
		mpsc::{channel, Sender},
		Arc,
	},
	thread,
	time::Duration,
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
mod parentchain_handler;
mod prometheus_metrics;
mod setup;
mod sidechain_setup;
mod sync_block_broadcaster;
mod sync_state;
#[cfg(feature = "teeracle")]
mod teeracle;
mod tests;
mod utils;
mod worker;
mod worker_peers_updater;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub type EnclaveWorker =
	Worker<Config, NodeApiFactory, Enclave, InitializationHandler<WorkerModeProvider>>;

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

	info!("*** Running worker in mode: {:?} \n", WorkerModeProvider::worker_mode());

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
	let sync_block_broadcaster =
		Arc::new(SyncBlockBroadcaster::new(tokio_handle.clone(), worker.clone()));
	let peer_updater = Arc::new(WorkerPeersUpdater::new(worker));
	let untrusted_peer_fetcher = UntrustedPeerFetcher::new(node_api_factory.clone());
	let peer_sidechain_block_fetcher =
		Arc::new(BlockFetcher::<SignedSidechainBlock, _>::new(untrusted_peer_fetcher));
	let enclave_metrics_receiver = Arc::new(EnclaveMetricsReceiver {});

	// initialize o-call bridge with a concrete factory implementation
	OCallBridge::initialize(Arc::new(OCallBridgeComponentFactory::new(
		node_api_factory.clone(),
		sync_block_broadcaster,
		enclave.clone(),
		sidechain_blockstorage.clone(),
		peer_updater,
		peer_sidechain_block_fetcher,
		tokio_handle.clone(),
		enclave_metrics_receiver,
	)));

	if let Some(run_config) = &config.run_config {
		let shard = extract_shard(&run_config.shard, enclave.as_ref());

		println!("Worker Config: {:?}", config);

		if clean_reset {
			setup::initialize_shard_and_keys(enclave.as_ref(), &shard).unwrap();
		}

		let node_api =
			node_api_factory.create_api().expect("Failed to create parentchain node API");

		if run_config.request_state {
			sync_state::sync_state::<_, _, WorkerModeProvider>(
				&node_api,
				&shard,
				enclave.as_ref(),
				run_config.skip_ra,
			);
		}

		start_worker::<_, _, _, _, WorkerModeProvider>(
			config,
			&shard,
			enclave,
			sidechain_blockstorage,
			node_api,
			tokio_handle,
			initialization_handler,
		);
	} else if let Some(smatches) = matches.subcommand_matches("request-state") {
		println!("*** Requesting state from a registered worker \n");
		let node_api =
			node_api_factory.create_api().expect("Failed to create parentchain node API");
		sync_state::sync_state::<_, _, WorkerModeProvider>(
			&node_api,
			&extract_shard(&smatches.value_of("shard").map(|s| s.to_string()), enclave.as_ref()),
			enclave.as_ref(),
			smatches.is_present("skip-ra"),
		);
	} else if matches.is_present("shielding-key") {
		setup::generate_shielding_key_file(enclave.as_ref());
	} else if matches.is_present("signing-key") {
		setup::generate_signing_key_file(enclave.as_ref());
	} else if matches.is_present("dump-ra") {
		info!("*** Perform RA and dump cert to disk");
		#[cfg(not(feature = "dcap"))]
		enclave.dump_ias_ra_cert_to_disk().unwrap();
		#[cfg(feature = "dcap")]
		enclave.dump_dcap_ra_cert_to_disk().unwrap();
	} else if matches.is_present("mrenclave") {
		println!("{}", enclave.get_mrenclave().unwrap().encode().to_base58());
	} else if let Some(sub_matches) = matches.subcommand_matches("init-shard") {
		setup::init_shard(
			enclave.as_ref(),
			&extract_shard(&sub_matches.value_of("shard").map(|s| s.to_string()), enclave.as_ref()),
		);
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
			let shard = extract_shard(
				&sub_matches.value_of("shard").map(|s| s.to_string()),
				enclave.as_ref(),
			);
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
fn start_worker<E, T, D, InitializationHandler, WorkerModeProvider>(
	config: Config,
	shard: &ShardIdentifier,
	enclave: Arc<E>,
	sidechain_storage: Arc<D>,
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
		+ TeeracleApi
		+ Clone,
	D: BlockPruner + FetchBlocks<SignedSidechainBlock> + Sync + Send + 'static,
	InitializationHandler: TrackInitialization + IsInitialized + Sync + Send + 'static,
	WorkerModeProvider: ProvideWorkerMode,
{
	let run_config = config.run_config.clone().expect("Run config missing");
	let skip_ra = run_config.skip_ra;

	println!("Integritee Worker v{}", VERSION);
	info!("starting worker on shard {}", shard.encode().to_base58());
	// ------------------------------------------------------------------------
	// check for required files
	if !skip_ra {
		check_files();
	}
	// ------------------------------------------------------------------------
	// initialize the enclave
	let mrenclave = enclave.get_mrenclave().unwrap();
	println!("MRENCLAVE={}", mrenclave.to_base58());
	println!("MRENCLAVE in hex {:?}", hex::encode(mrenclave));

	// ------------------------------------------------------------------------
	// let new workers call us for key provisioning
	println!("MU-RA server listening on {}", config.mu_ra_url());
	let is_development_mode = run_config.dev;
	let ra_url = config.mu_ra_url();
	let enclave_api_key_prov = enclave.clone();
	thread::spawn(move || {
		enclave_run_state_provisioning_server(
			enclave_api_key_prov.as_ref(),
			sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
			&ra_url,
			skip_ra,
		);
		info!("State provisioning server stopped.");
	});

	let tokio_handle = tokio_handle_getter.get_handle();

	#[cfg(feature = "teeracle")]
	let teeracle_tokio_handle = tokio_handle.clone();

	// ------------------------------------------------------------------------
	// Get the public key of our TEE.
	let tee_accountid = enclave_account(enclave.as_ref());
	println!("Enclave account {:} ", &tee_accountid.to_ss58check());

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
	if WorkerModeProvider::worker_mode() == WorkerMode::Sidechain
		|| WorkerModeProvider::worker_mode() == WorkerMode::OffChainWorker
	{
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
	}

	// ------------------------------------------------------------------------
	// Start untrusted worker rpc server.
	// i.e move sidechain block importing to trusted worker.
	if WorkerModeProvider::worker_mode() == WorkerMode::Sidechain {
		sidechain_start_untrusted_rpc_server(
			&config,
			enclave.clone(),
			sidechain_storage.clone(),
			tokio_handle,
		);
	}

	// ------------------------------------------------------------------------
	// Init parentchain specific stuff. Needed for parentchain communication.
	let parentchain_handler = Arc::new(
		ParentchainHandler::new_with_automatic_light_client_allocation(
			node_api.clone(),
			enclave.clone(),
		)
		.unwrap(),
	);
	let last_synced_header = parentchain_handler.init_parentchain_components().unwrap();
	let nonce = node_api.get_nonce_of(&tee_accountid).unwrap();
	info!("Enclave nonce = {:?}", nonce);
	enclave
		.set_nonce(nonce)
		.expect("Could not set nonce of enclave. Returning here...");

	let metadata = node_api.metadata.clone();
	let runtime_spec_version = node_api.runtime_version.spec_version;
	let runtime_transaction_version = node_api.runtime_version.transaction_version;
	enclave
		.set_node_metadata(
			NodeMetadata::new(metadata, runtime_spec_version, runtime_transaction_version).encode(),
		)
		.expect("Could not set the node metadata in the enclave");

	// ------------------------------------------------------------------------
	// Perform a remote attestation and get an unchecked extrinsic back.
	let trusted_url = config.trusted_worker_url_external();
	if skip_ra {
		println!(
			"[!] skipping remote attestation. Registering enclave without attestation report."
		);
	} else {
		println!("[!] creating remote attestation report and create enclave register extrinsic.");
	};
	#[cfg(not(feature = "dcap"))]
	let uxt = enclave.generate_ias_ra_extrinsic(&trusted_url, skip_ra).unwrap();
	#[cfg(feature = "dcap")]
	let uxt = enclave.generate_dcap_ra_extrinsic(&trusted_url, skip_ra).unwrap();

	let mut xthex = hex::encode(uxt);
	xthex.insert_str(0, "0x");

	// Account funds
	if let Err(x) =
		setup_account_funding(&node_api, &tee_accountid, xthex.clone(), is_development_mode)
	{
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

	// ------------------------------------------------------------------------
	// initialize teeracle interval
	#[cfg(feature = "teeracle")]
	if WorkerModeProvider::worker_mode() == WorkerMode::Teeracle {
		start_interval_market_update(
			&node_api,
			run_config.teeracle_update_interval,
			enclave.as_ref(),
			&teeracle_tokio_handle,
		);
	}

	if WorkerModeProvider::worker_mode() != WorkerMode::Teeracle {
		println!("*** [+] Finished syncing light client, syncing parentchain...");

		// Syncing all parentchain blocks, this might take a while..
		let mut last_synced_header =
			parentchain_handler.sync_parentchain(last_synced_header).unwrap();

		// ------------------------------------------------------------------------
		// Initialize the sidechain
		if WorkerModeProvider::worker_mode() == WorkerMode::Sidechain {
			last_synced_header = sidechain_init_block_production(
				enclave,
				&register_enclave_xt_header,
				we_are_primary_validateer,
				parentchain_handler.clone(),
				sidechain_storage,
				&last_synced_header,
			)
			.unwrap();
		}

		// ------------------------------------------------------------------------
		// start parentchain syncing loop (subscribe to header updates)
		thread::Builder::new()
			.name("parentchain_sync_loop".to_owned())
			.spawn(move || {
				if let Err(e) =
					subscribe_to_parentchain_new_headers(parentchain_handler, last_synced_header)
				{
					error!("Parentchain block syncing terminated with a failure: {:?}", e);
				}
				println!("[!] Parentchain block syncing has terminated");
			})
			.unwrap();
	}

	// ------------------------------------------------------------------------
	if WorkerModeProvider::worker_mode() == WorkerMode::Sidechain {
		spawn_worker_for_shard_polling(shard, node_api.clone(), initialization_handler);
	}

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
/// considered initialized and ready for the next worker to start (in sidechain mode only).
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

type Events = Vec<frame_system::EventRecord<RuntimeEvent, Hash>>;

fn parse_events(event: String) -> Result<Events, String> {
	let _unhex = Vec::from_hex(event).map_err(|_| "Decoding Events Failed".to_string())?;
	let mut _er_enc = _unhex.as_slice();
	Events::decode(&mut _er_enc).map_err(|_| "Decoding Events Failed".to_string())
}

fn print_events(events: Events, _sender: Sender<String>) {
	for evr in &events {
		debug!("Decoded: phase = {:?}, event = {:?}", evr.phase, evr.event);
		match &evr.event {
			RuntimeEvent::Balances(be) => {
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
			RuntimeEvent::Teerex(re) => {
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
						block_number,
					) => {
						info!("[+] Received ProcessedParentchainBlock event");
						debug!("    From:    {:?}", sender);
						debug!("    Block Hash: {:?}", hex::encode(block_hash));
						debug!("    Merkle Root: {:?}", hex::encode(merkle_root));
						debug!("    Block Number: {:?}", block_number);
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
			#[cfg(feature = "teeracle")]
			RuntimeEvent::Teeracle(re) => {
				debug!("{:?}", re);
				match &re {
					my_node_runtime::pallet_teeracle::Event::ExchangeRateUpdated(
						source,
						currency,
						new_value,
					) => {
						println!("[+] Received ExchangeRateUpdated event");
						println!("    Data source:  {}", source);
						println!("    Currency:  {}", currency);
						println!("    Exchange rate: {:?}", new_value);
					},
					my_node_runtime::pallet_teeracle::Event::ExchangeRateDeleted(
						source,
						currency,
					) => {
						println!("[+] Received ExchangeRateDeleted event");
						println!("    Data source:  {}", source);
						println!("    Currency:  {}", currency);
					},
					my_node_runtime::pallet_teeracle::Event::AddedToWhitelist(
						source,
						mrenclave,
					) => {
						println!("[+] Received AddedToWhitelist event");
						println!("    Data source:  {}", source);
						println!("    Currency:  {:?}", mrenclave);
					},
					my_node_runtime::pallet_teeracle::Event::RemovedFromWhitelist(
						source,
						mrenclave,
					) => {
						println!("[+] Received RemovedFromWhitelist event");
						println!("    Data source:  {}", source);
						println!("    Currency:  {:?}", mrenclave);
					},
					_ => {
						trace!("Ignoring unsupported pallet_teeracle event");
					},
				}
			},
			#[cfg(feature = "sidechain")]
			RuntimeEvent::Sidechain(re) => match &re {
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

/// Subscribe to the node API finalized heads stream and trigger a parent chain sync
/// upon receiving a new header.
fn subscribe_to_parentchain_new_headers<E: EnclaveBase + Sidechain>(
	parentchain_handler: Arc<ParentchainHandler<ParentchainApi, E>>,
	mut last_synced_header: Header,
) -> Result<(), Error> {
	let (sender, receiver) = channel();
	//TODO: this should be implemented by parentchain_handler directly, and not via
	// exposed parentchain_api. Blocked by https://github.com/scs/substrate-api-client/issues/267.
	parentchain_handler
		.parentchain_api()
		.subscribe_finalized_heads(sender)
		.map_err(Error::ApiClient)?;

	loop {
		let new_header: Header = match receiver.recv() {
			Ok(header_str) => serde_json::from_str(&header_str).map_err(Error::Serialization),
			Err(e) => Err(Error::ApiSubscriptionDisconnected(e)),
		}?;

		println!(
			"[+] Received finalized header update ({}), syncing parent chain...",
			new_header.number
		);

		last_synced_header = parentchain_handler.sync_parentchain(last_synced_header)?;
	}
}

/// Get the public signing key of the TEE.
fn enclave_account<E: EnclaveBase>(enclave_api: &E) -> AccountId32 {
	let tee_public = enclave_api.get_ecc_signing_pubkey().unwrap();
	trace!("[+] Got ed25519 account of TEE = {}", tee_public.to_ss58check());
	AccountId32::from(*tee_public.as_array_ref())
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
