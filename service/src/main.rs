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
use crate::teeracle::{schedule_periodic_reregistration_thread, start_periodic_market_update};

#[cfg(not(feature = "dcap"))]
use crate::utils::check_files;

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
	utils::extract_shard,
	worker::Worker,
	worker_peers_updater::WorkerPeersUpdater,
};
use base58::ToBase58;
use clap::{load_yaml, App};
use codec::Encode;
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
use itp_settings::worker_mode::{ProvideWorkerMode, WorkerMode, WorkerModeProvider};
use its_peer_fetch::{
	block_fetch_client::BlockFetcher, untrusted_peer_fetch::UntrustedPeerFetcher,
};
use its_primitives::types::block::SignedBlock as SignedSidechainBlock;
use its_storage::{interface::FetchBlocks, BlockPruner, SidechainStorageLock};
use log::*;
use my_node_runtime::{Hash, Header, RuntimeEvent};
use sgx_types::*;
use sp_runtime::traits::Header as HeaderT;
use substrate_api_client::{
	api::XtStatus, rpc::HandleSubscription, GetHeader, SubmitAndWatch, SubscribeChain,
	SubscribeEvents,
};
use teerex_primitives::AnySigner;

#[cfg(feature = "dcap")]
use sgx_verify::extract_tcb_info_from_raw_dcap_quote;

use enclave_bridge_primitives::ShardIdentifier;
use itc_parentchain::primitives::ParentchainId;
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_keyring::AccountKeyring;
use sp_runtime::MultiSigner;
use std::{str, sync::Arc, thread, time::Duration};

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
pub type Event = substrate_api_client::EventRecord<RuntimeEvent, Hash>;

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
		setup::purge_files_from_dir(config.data_dir()).unwrap();
	}

	// build the entire dependency tree
	let tokio_handle = Arc::new(GlobalTokioHandle {});
	let sidechain_blockstorage = Arc::new(
		SidechainStorageLock::<SignedSidechainBlock>::from_base_path(
			config.data_dir().to_path_buf(),
		)
		.unwrap(),
	);
	let node_api_factory = Arc::new(NodeApiFactory::new(
		config.integritee_rpc_endpoint(),
		AccountKeyring::Alice.pair(),
	));
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

	let maybe_target_a_parentchain_api_factory = config
		.target_a_parentchain_rpc_endpoint()
		.map(|url| Arc::new(NodeApiFactory::new(url, AccountKeyring::Alice.pair())));

	let maybe_target_b_parentchain_api_factory = config
		.target_b_parentchain_rpc_endpoint()
		.map(|url| Arc::new(NodeApiFactory::new(url, AccountKeyring::Alice.pair())));

	// initialize o-call bridge with a concrete factory implementation
	OCallBridge::initialize(Arc::new(OCallBridgeComponentFactory::new(
		node_api_factory.clone(),
		maybe_target_a_parentchain_api_factory,
		maybe_target_b_parentchain_api_factory,
		sync_block_broadcaster,
		enclave.clone(),
		sidechain_blockstorage.clone(),
		peer_updater,
		peer_sidechain_block_fetcher,
		tokio_handle.clone(),
		enclave_metrics_receiver,
	)));

	let quoting_enclave_target_info = match enclave.qe_get_target_info() {
		Ok(target_info) => Some(target_info),
		Err(e) => {
			warn!("Setting up DCAP - qe_get_target_info failed with error: {:#?}, continuing.", e);
			None
		},
	};
	let quote_size = match enclave.qe_get_quote_size() {
		Ok(size) => Some(size),
		Err(e) => {
			warn!("Setting up DCAP - qe_get_quote_size failed with error: {:#?}, continuing.", e);
			None
		},
	};

	if let Some(run_config) = config.run_config() {
		let shard = extract_shard(run_config.shard(), enclave.as_ref());

		println!("Worker Config: {:?}", config);

		if clean_reset {
			setup::initialize_shard_and_keys(enclave.as_ref(), &shard).unwrap();
		}

		let node_api =
			node_api_factory.create_api().expect("Failed to create parentchain node API");

		if run_config.request_state() {
			sync_state::sync_state::<_, _, WorkerModeProvider>(
				&node_api,
				&shard,
				enclave.as_ref(),
				run_config.skip_ra(),
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
			quoting_enclave_target_info,
			quote_size,
		);
	} else if let Some(smatches) = matches.subcommand_matches("request-state") {
		println!("*** Requesting state from a registered worker \n");
		let node_api =
			node_api_factory.create_api().expect("Failed to create parentchain node API");
		sync_state::sync_state::<_, _, WorkerModeProvider>(
			&node_api,
			&extract_shard(smatches.value_of("shard"), enclave.as_ref()),
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
		{
			let skip_ra = false;
			let dcap_quote = enclave.generate_dcap_ra_quote(skip_ra).unwrap();
			let (fmspc, _tcb_info) = extract_tcb_info_from_raw_dcap_quote(&dcap_quote).unwrap();
			enclave.dump_dcap_collateral_to_disk(fmspc).unwrap();
			enclave.dump_dcap_ra_cert_to_disk().unwrap();
		}
	} else if matches.is_present("mrenclave") {
		println!("{}", enclave.get_fingerprint().unwrap().encode().to_base58());
	} else if let Some(sub_matches) = matches.subcommand_matches("init-shard") {
		setup::init_shard(
			enclave.as_ref(),
			&extract_shard(sub_matches.value_of("shard"), enclave.as_ref()),
		);
	} else if let Some(sub_matches) = matches.subcommand_matches("test") {
		if sub_matches.is_present("provisioning-server") {
			println!("*** Running Enclave MU-RA TLS server\n");
			enclave_run_state_provisioning_server(
				enclave.as_ref(),
				sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
				quoting_enclave_target_info.as_ref(),
				quote_size.as_ref(),
				&config.mu_ra_url(),
				sub_matches.is_present("skip-ra"),
			);
			println!("[+] Done!");
		} else if sub_matches.is_present("provisioning-client") {
			println!("*** Running Enclave MU-RA TLS client\n");
			let shard = extract_shard(sub_matches.value_of("shard"), enclave.as_ref());
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
	integritee_rpc_api: ParentchainApi,
	tokio_handle_getter: Arc<T>,
	initialization_handler: Arc<InitializationHandler>,
	quoting_enclave_target_info: Option<sgx_target_info_t>,
	quote_size: Option<u32>,
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
	let run_config = config.run_config().clone().expect("Run config missing");
	let skip_ra = run_config.skip_ra();

	#[cfg(feature = "teeracle")]
	let flavor_str = "teeracle";
	#[cfg(feature = "sidechain")]
	let flavor_str = "sidechain";
	#[cfg(feature = "offchain-worker")]
	let flavor_str = "offchain-worker";
	#[cfg(not(any(feature = "offchain-worker", feature = "sidechain", feature = "teeracle")))]
	let flavor_str = "offchain-worker";

	println!("Integritee Worker for {} v{}", flavor_str, VERSION);

	#[cfg(feature = "dcap")]
	println!("  DCAP is enabled");
	#[cfg(not(feature = "dcap"))]
	println!("  DCAP is disabled");
	#[cfg(feature = "production")]
	println!("  Production Mode is enabled");
	#[cfg(not(feature = "production"))]
	println!("  Production Mode is disabled");
	#[cfg(feature = "evm")]
	println!("  EVM is enabled");
	#[cfg(not(feature = "evm"))]
	println!("  EVM is disabled");

	info!("starting worker on shard {}", shard.encode().to_base58());
	// ------------------------------------------------------------------------
	// check for required files
	if !skip_ra {
		#[cfg(not(feature = "dcap"))]
		check_files();
	}
	// ------------------------------------------------------------------------
	// initialize the enclave
	let mrenclave = enclave.get_fingerprint().unwrap();
	println!("MRENCLAVE={}", mrenclave.0.to_base58());
	println!("MRENCLAVE in hex {:?}", hex::encode(mrenclave));

	// ------------------------------------------------------------------------
	// let new workers call us for key provisioning
	println!("MU-RA server listening on {}", config.mu_ra_url());
	let is_development_mode = run_config.dev();
	let ra_url = config.mu_ra_url();
	let enclave_api_key_prov = enclave.clone();
	thread::spawn(move || {
		enclave_run_state_provisioning_server(
			enclave_api_key_prov.as_ref(),
			sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
			quoting_enclave_target_info.as_ref(),
			quote_size.as_ref(),
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
	if config.enable_metrics_server() {
		let enclave_wallet = Arc::new(EnclaveAccountInfoProvider::new(
			integritee_rpc_api.clone(),
			tee_accountid.clone(),
		));
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

	let (parentchain_handler, last_synced_header) =
		init_parentchain(&enclave, &integritee_rpc_api, &tee_accountid, ParentchainId::Integritee);

	#[cfg(feature = "dcap")]
	register_collateral(
		&integritee_rpc_api,
		&*enclave,
		&tee_accountid,
		is_development_mode,
		skip_ra,
	);

	let trusted_url = config.trusted_worker_url_external();

	#[cfg(feature = "attesteer")]
	fetch_marblerun_events_every_hour(
		integritee_rpc_api.clone(),
		enclave.clone(),
		tee_accountid.clone(),
		is_development_mode,
		trusted_url.clone(),
		run_config.marblerun_base_url().to_string(),
	);

	// ------------------------------------------------------------------------
	// Perform a remote attestation and get an unchecked extrinsic back.

	if skip_ra {
		println!(
			"[!] skipping remote attestation. Registering enclave without attestation report."
		);
	} else {
		println!("[!] creating remote attestation report and create enclave register extrinsic.");
	};

	#[cfg(feature = "dcap")]
	enclave.set_sgx_qpl_logging().expect("QPL logging setup failed");

	let enclave2 = enclave.clone();
	#[cfg(not(feature = "dcap"))]
	let register_xt = move || enclave2.generate_ias_ra_extrinsic(&trusted_url, skip_ra).unwrap();
	#[cfg(feature = "dcap")]
	let register_xt = move || enclave2.generate_dcap_ra_extrinsic(&trusted_url, skip_ra).unwrap();

	// clones because of the move
	let node_api2 = integritee_rpc_api.clone();
	let tee_accountid_clone = tee_accountid.clone();
	let send_register_xt = move || {
		println!("[+] Send register enclave extrinsic");
		send_extrinsic(register_xt(), &node_api2, &tee_accountid_clone, is_development_mode)
	};

	let register_enclave_block_hash = send_register_xt().unwrap();

	let register_enclave_xt_header = integritee_rpc_api
		.get_header(Some(register_enclave_block_hash))
		.unwrap()
		.unwrap();

	println!(
		"[+] Enclave registered at block number: {:?}, hash: {:?}",
		register_enclave_xt_header.number(),
		register_enclave_xt_header.hash()
	);

	let we_are_primary_validateer =
		we_are_primary_worker(&integritee_rpc_api, shard, &tee_accountid).unwrap();

	if we_are_primary_validateer {
		println!("[+] We are the primary worker");
	} else {
		println!("[+] We are NOT the primary worker");
	}

	initialization_handler.registered_on_parentchain();

	// ------------------------------------------------------------------------
	// initialize teeracle interval
	#[cfg(feature = "teeracle")]
	if WorkerModeProvider::worker_mode() == WorkerMode::Teeracle {
		schedule_periodic_reregistration_thread(
			send_register_xt,
			run_config.reregister_teeracle_interval(),
		);

		start_periodic_market_update(
			&integritee_rpc_api,
			run_config.teeracle_update_interval(),
			enclave.as_ref(),
			&teeracle_tokio_handle,
		);
	}

	if WorkerModeProvider::worker_mode() != WorkerMode::Teeracle {
		println!("*** [+] Finished initializing light client, syncing parentchain...");

		// Syncing all parentchain blocks, this might take a while..
		let mut last_synced_header =
			parentchain_handler.sync_parentchain(last_synced_header).unwrap();

		// ------------------------------------------------------------------------
		// Initialize the sidechain
		if WorkerModeProvider::worker_mode() == WorkerMode::Sidechain {
			last_synced_header = sidechain_init_block_production(
				enclave.clone(),
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
		spawn_worker_for_shard_polling(shard, integritee_rpc_api.clone(), initialization_handler);
	}

	if let Some(url) = config.target_a_parentchain_rpc_endpoint() {
		init_target_parentchain(
			&enclave,
			&tee_accountid,
			url,
			ParentchainId::TargetA,
			is_development_mode,
		)
	}

	if let Some(url) = config.target_b_parentchain_rpc_endpoint() {
		init_target_parentchain(
			&enclave,
			&tee_accountid,
			url,
			ParentchainId::TargetB,
			is_development_mode,
		)
	}

	// ------------------------------------------------------------------------
	// Subscribe to events and print them.
	println!("*** [{:?}] Subscribing to events", ParentchainId::Integritee);
	let mut subscription = integritee_rpc_api.subscribe_events().unwrap();
	println!("[+] [{:?}] Subscribed to events. waiting...", ParentchainId::Integritee);
	loop {
		if let Some(Ok(events)) = subscription.next_event::<RuntimeEvent, Hash>() {
			print_events(events)
		}
	}
}

fn init_target_parentchain<E>(
	enclave: &Arc<E>,
	tee_account_id: &AccountId32,
	url: String,
	parentchain_id: ParentchainId,
	is_development_mode: bool,
) where
	E: EnclaveBase + Sidechain,
{
	println!("Initializing parentchain {:?} with url: {}", parentchain_id, url);
	let node_api = NodeApiFactory::new(url, AccountKeyring::Alice.pair())
		.create_api()
		.unwrap_or_else(|_| panic!("[{:?}] Failed to create parentchain node API", parentchain_id));

	// some random bytes not too small to ensure that the enclave has enough funds
	setup_account_funding(&node_api, tee_account_id, [0u8; 100].into(), is_development_mode)
		.unwrap_or_else(|_| {
			panic!("[{:?}] Could not fund parentchain enclave account", parentchain_id)
		});

	let (parentchain_handler, last_synched_header) =
		init_parentchain(enclave, &node_api, tee_account_id, parentchain_id);

	if WorkerModeProvider::worker_mode() != WorkerMode::Teeracle {
		println!(
			"*** [+] [{:?}] Finished initializing light client, syncing parentchain...",
			parentchain_id
		);

		// Syncing all parentchain blocks, this might take a while..
		let last_synched_header =
			parentchain_handler.sync_parentchain(last_synched_header).unwrap();

		// start parentchain syncing loop (subscribe to header updates)
		thread::Builder::new()
			.name(format!("{:?}_parentchain_sync_loop", parentchain_id))
			.spawn(move || {
				if let Err(e) =
					subscribe_to_parentchain_new_headers(parentchain_handler, last_synched_header)
				{
					error!(
						"[{:?}] parentchain block syncing terminated with a failure: {:?}",
						parentchain_id, e
					);
				}
				println!("[!] [{:?}] parentchain block syncing has terminated", parentchain_id);
			})
			.unwrap();
	}

	// Subscribe to events and print them.
	println!("*** [{:?}] Subscribing to events...", parentchain_id);
	let mut subscription = node_api.subscribe_events().unwrap();
	println!("[+] [{:?}] Subscribed to events. waiting...", parentchain_id);

	thread::Builder::new()
		.name(format!("{:?}_parentchain_event_subscription", parentchain_id))
		.spawn(move || loop {
			if let Some(Ok(events)) = subscription.next_event::<RuntimeEvent, Hash>() {
				print_events(events)
			}
		})
		.unwrap();
}

fn init_parentchain<E>(
	enclave: &Arc<E>,
	node_api: &ParentchainApi,
	tee_account_id: &AccountId32,
	parentchain_id: ParentchainId,
) -> (Arc<ParentchainHandler<ParentchainApi, E>>, Header)
where
	E: EnclaveBase + Sidechain,
{
	let parentchain_handler = Arc::new(
		ParentchainHandler::new_with_automatic_light_client_allocation(
			node_api.clone(),
			enclave.clone(),
			parentchain_id,
		)
		.unwrap(),
	);
	let last_synced_header = parentchain_handler.init_parentchain_components().unwrap();
	println!("[{:?}] last synced parentchain block: {}", parentchain_id, last_synced_header.number);

	let nonce = node_api.get_nonce_of(tee_account_id).unwrap();
	info!("[{:?}] Enclave nonce = {:?}", parentchain_id, nonce);
	enclave.set_nonce(nonce, parentchain_id).unwrap_or_else(|_| {
		panic!("[{:?}] Could not set nonce of enclave. Returning here...", parentchain_id)
	});

	let metadata = node_api.metadata().clone();
	let runtime_spec_version = node_api.runtime_version().spec_version;
	let runtime_transaction_version = node_api.runtime_version().transaction_version;
	enclave
		.set_node_metadata(
			NodeMetadata::new(metadata, runtime_spec_version, runtime_transaction_version).encode(),
			parentchain_id,
		)
		.unwrap_or_else(|_| {
			panic!("[{:?}] Could not set the node metadata in the enclave", parentchain_id)
		});

	(parentchain_handler, last_synced_header)
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
			if let Ok(Some(enclave)) =
				node_api.primary_worker_for_shard(&shard_for_initialized, None)
			{
				// Set that the service is initialized.
				initialization_handler.worker_for_shard_registered();
				println!(
					"[+] Found `WorkerForShard` on parentchain state: {:?}",
					enclave.instance_signer()
				);
				break
			}
			thread::sleep(Duration::from_secs(POLL_INTERVAL_SECS));
		}
	});
}

fn print_events(events: Vec<Event>) {
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
					my_node_runtime::pallet_teerex::Event::AddedSgxEnclave {
						registered_by,
						worker_url,
						..
					} => {
						println!("[+] Received AddedEnclave event");
						println!("    Sender (Worker):  {:?}", registered_by);
						println!(
							"    Registered URL: {:?}",
							str::from_utf8(&worker_url.clone().unwrap_or("none".into())).unwrap()
						);
					},
					_ => {
						trace!("Ignoring unsupported pallet_teerex event");
					},
				}
			},
			RuntimeEvent::EnclaveBridge(re) => {
				debug!("{:?}", re);
				match &re {
					my_node_runtime::pallet_enclave_bridge::Event::IndirectInvocationRegistered(
						shard,
					) => {
						println!(
							"[+] Received trusted call for shard {}",
							shard.encode().to_base58()
						);
					},
					my_node_runtime::pallet_enclave_bridge::Event::ProcessedParentchainBlock {
						shard,
						block_hash,
						trusted_calls_merkle_root,
						block_number,
					} => {
						info!("[+] Received ProcessedParentchainBlock event");
						debug!("    for shard:    {:?}", shard);
						debug!("    Block Hash: {:?}", hex::encode(block_hash));
						debug!("    Merkle Root: {:?}", hex::encode(trusted_calls_merkle_root));
						debug!("    Block Number: {:?}", block_number);
					},
					my_node_runtime::pallet_enclave_bridge::Event::ShieldFunds {
						shard,
						encrypted_beneficiary,
						amount,
					} => {
						info!("[+] Received ShieldFunds event");
						debug!("    for shard:    {:?}", shard);
						debug!("    for enc. beneficiary:    {:?}", encrypted_beneficiary);
						debug!("    Amount:    {:?}", amount);
					},
					my_node_runtime::pallet_enclave_bridge::Event::UnshieldedFunds {
						shard,
						beneficiary,
						amount,
					} => {
						info!("[+] Received UnshieldedFunds event");
						debug!("    for shard:    {:?}", shard);
						debug!("    beneficiary:    {:?}", beneficiary);
						debug!("    Amount:    {:?}", amount);
					},
					_ => {
						trace!("Ignoring unsupported pallet_enclave_bridge event");
					},
				}
			},
			#[cfg(feature = "teeracle")]
			RuntimeEvent::Teeracle(re) => {
				debug!("{:?}", re);
				match &re {
					my_node_runtime::pallet_teeracle::Event::ExchangeRateUpdated {
						data_source,
						trading_pair,
						exchange_rate,
					} => {
						println!("[+] Received ExchangeRateUpdated event");
						println!("    Data source:  {}", data_source);
						println!("    trading pair:  {}", trading_pair);
						println!("    Exchange rate: {:?}", exchange_rate);
					},
					my_node_runtime::pallet_teeracle::Event::ExchangeRateDeleted {
						data_source,
						trading_pair,
					} => {
						println!("[+] Received ExchangeRateDeleted event");
						println!("    Data source:  {}", data_source);
						println!("    trading pair:  {}", trading_pair);
					},
					my_node_runtime::pallet_teeracle::Event::AddedToWhitelist {
						data_source,
						enclave_fingerprint,
					} => {
						println!("[+] Received AddedToWhitelist event");
						println!("    Data source:  {}", data_source);
						println!("    fingerprint:  {:?}", enclave_fingerprint);
					},
					my_node_runtime::pallet_teeracle::Event::RemovedFromWhitelist {
						data_source,
						enclave_fingerprint,
					} => {
						println!("[+] Received RemovedFromWhitelist event");
						println!("    Data source:  {}", data_source);
						println!("    fingerprint:  {:?}", enclave_fingerprint);
					},
					_ => {
						trace!("Ignoring unsupported pallet_teeracle event");
					},
				}
			},
			#[cfg(feature = "sidechain")]
			RuntimeEvent::Sidechain(re) => match &re {
				my_node_runtime::pallet_sidechain::Event::FinalizedSidechainBlock {
					shard,
					block_header_hash,
					validateer,
				} => {
					info!("[+] Received FinalizedSidechainBlock event");
					debug!("    for shard:    {:?}", shard);
					debug!("    From:    {:?}", hex::encode(block_header_hash));
					debug!("    validateer: {:?}", validateer);
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

#[cfg(feature = "attesteer")]
fn fetch_marblerun_events_every_hour<E>(
	api: ParentchainApi,
	enclave: Arc<E>,
	accountid: AccountId32,
	is_development_mode: bool,
	url: String,
	marblerun_base_url: String,
) where
	E: RemoteAttestation + Clone + Sync + Send + 'static,
{
	let enclave = enclave.clone();
	let handle = thread::spawn(move || {
		const POLL_INTERVAL_5_MINUTES_IN_SECS: u64 = 5 * 60;
		loop {
			info!("Polling marblerun events for quotes to register");
			register_quotes_from_marblerun(
				&api,
				enclave.clone(),
				&accountid,
				is_development_mode,
				url.clone(),
				&marblerun_base_url,
			);

			thread::sleep(Duration::from_secs(POLL_INTERVAL_5_MINUTES_IN_SECS));
		}
	});

	handle.join().unwrap()
}
#[cfg(feature = "attesteer")]
fn register_quotes_from_marblerun(
	api: &ParentchainApi,
	enclave: Arc<dyn RemoteAttestation>,
	accountid: &AccountId32,
	is_development_mode: bool,
	url: String,
	marblerun_base_url: &str,
) {
	let enclave = enclave.as_ref();
	let events = prometheus_metrics::fetch_marblerun_events(marblerun_base_url)
		.map_err(|e| {
			info!("Fetching events from Marblerun failed with: {:?}, continuing with 0 events.", e);
		})
		.unwrap_or_default();
	let quotes: Vec<&[u8]> =
		events.iter().map(|event| event.get_quote_without_prepended_bytes()).collect();

	for quote in quotes {
		match enclave.generate_dcap_ra_extrinsic_from_quote(url.clone(), &quote) {
			Ok(xt) => {
				send_extrinsic(xt, api, accountid, is_development_mode);
			},
			Err(e) => {
				error!("Extracting information from quote failed: {}", e)
			},
		}
	}
}
#[cfg(feature = "dcap")]
fn register_collateral(
	api: &ParentchainApi,
	enclave: &dyn RemoteAttestation,
	accountid: &AccountId32,
	is_development_mode: bool,
	skip_ra: bool,
) {
	//TODO generate_dcap_ra_quote() does not really need skip_ra, rethink how many layers skip_ra should be passed along
	if !skip_ra {
		let dcap_quote = enclave.generate_dcap_ra_quote(skip_ra).unwrap();
		let (fmspc, _tcb_info) = extract_tcb_info_from_raw_dcap_quote(&dcap_quote).unwrap();
		println!("[>] DCAP setup: register QE collateral");
		let uxt = enclave.generate_register_quoting_enclave_extrinsic(fmspc).unwrap();
		send_extrinsic(uxt, api, accountid, is_development_mode);

		println!("[>] DCAP setup: register TCB info");
		let uxt = enclave.generate_register_tcb_info_extrinsic(fmspc).unwrap();
		send_extrinsic(uxt, api, accountid, is_development_mode);
	}
}

fn send_extrinsic(
	extrinsic: Vec<u8>,
	api: &ParentchainApi,
	fee_payer: &AccountId32,
	is_development_mode: bool,
) -> Option<Hash> {
	// ensure account funds
	if let Err(x) = setup_account_funding(api, fee_payer, extrinsic.clone(), is_development_mode) {
		error!("Ensure enclave funding failed: {:?}", x);
		// Return without registering the enclave. This will fail and the transaction will be banned for 30min.
		return None
	}

	info!("[>] send extrinsic");
	trace!("  encoded extrinsic: 0x{:}", hex::encode(extrinsic.clone()));

	// fixme: wait ...until_success doesn't work due to https://github.com/scs/substrate-api-client/issues/624
	// fixme: currently, we don't verify if the extrinsic was a success here
	match api.submit_and_watch_opaque_extrinsic_until(extrinsic.into(), XtStatus::Finalized) {
		Ok(xt_report) => {
			info!(
				"[+] L1 extrinsic success. extrinsic hash: {:?} / status: {:?}",
				xt_report.extrinsic_hash, xt_report.status
			);
			xt_report.block_hash
		},
		Err(e) => {
			error!("ExtrinsicFailed {:?}", e);
			None
		},
	}
}

/// Subscribe to the node API finalized heads stream and trigger a parent chain sync
/// upon receiving a new header.
fn subscribe_to_parentchain_new_headers<E: EnclaveBase + Sidechain>(
	parentchain_handler: Arc<ParentchainHandler<ParentchainApi, E>>,
	mut last_synced_header: Header,
) -> Result<(), Error> {
	// TODO: this should be implemented by parentchain_handler directly, and not via
	// exposed parentchain_api
	let mut subscription = parentchain_handler
		.parentchain_api()
		.subscribe_finalized_heads()
		.map_err(Error::ApiClient)?;

	loop {
		let new_header = subscription
			.next()
			.ok_or(Error::ApiSubscriptionDisconnected)?
			.map_err(|e| Error::ApiClient(e.into()))?;

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
fn we_are_primary_worker(
	node_api: &ParentchainApi,
	shard: &ShardIdentifier,
	enclave_account: &AccountId32,
) -> Result<bool, Error> {
	// are we registered? else fail.
	node_api
		.enclave(enclave_account, None)?
		.expect("our enclave should be registered at this point");
	trace!("our enclave is registered");
	match node_api.primary_worker_for_shard(shard, None).unwrap() {
		Some(enclave) =>
			match enclave.instance_signer() {
				AnySigner::Known(MultiSigner::Ed25519(primary)) =>
					if primary.encode() == enclave_account.encode() {
						debug!("We are primary worker on this shard adn we have been previously running.");
						Ok(true)
					} else {
						debug!("The primary worker is {}", primary.to_ss58check());
						Ok(false)
					},
				_ => {
					warn!("the primary worker is of unknown type");
					Ok(false)
				},
			},
		None => {
			debug!("We are the primary worker on this shard and the shard is untouched");
			Ok(true)
		},
	}
}
