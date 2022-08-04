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

extern crate chrono;
use crate::{
	command_utils::*, exchange_oracle::ExchangeOracleSubCommand, trusted_commands,
	trusted_commands::TrustedArgs, Cli,
};
use base58::{FromBase58, ToBase58};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use codec::{Decode, Encode};
use ita_stf::ShardIdentifier;
use itc_rpc_client::direct_client::DirectApi;
use itp_node_api::api_client::{PalletTeerexApi, TEEREX};
use itp_sgx_crypto::ShieldingCryptoEncrypt;
use log::*;
use my_node_runtime::{Balance, BalancesCall, Call, Event, Hash};
use sp_application_crypto::{ed25519, sr25519};
use sp_core::{crypto::Ss58Codec, sr25519 as sr25519_core, Pair};
use sp_keyring::AccountKeyring;
use std::{
	path::PathBuf,
	sync::mpsc::channel,
	time::{Duration, UNIX_EPOCH},
};
use substrate_api_client::{
	compose_extrinsic, compose_extrinsic_offline, utils::FromHexString, GenericAddress, Metadata,
	UncheckedExtrinsicV4, XtStatus,
};
use substrate_client_keystore::{KeystoreExt, LocalKeystore};

const PREFUNDING_AMOUNT: u128 = 1_000_000_000;

#[derive(Subcommand)]
pub enum Commands {
	/// query parentchain balance for AccountId
	Balance {
		/// AccountId in ss58check format
		account: String,
	},

	/// generates a new account for the integritee chain in your local keystore
	NewAccount,

	/// lists all accounts in your local keystore for the integritee chain
	ListAccounts,

	/// query node metadata and print it as json to stdout
	PrintMetadata,

	/// query sgx-runtime metadata and print it as json to stdout
	PrintSgxMetadata,

	/// send some bootstrapping funds to supplied account(s)
	Faucet {
		/// Account(s) to be funded, ss58check encoded
		#[clap(min_values = 1, required = true)]
		accounts: Vec<String>,
	},

	/// transfer funds from one parentchain account to another
	Transfer {
		/// sender's AccountId in ss58check format
		from: String,

		/// recipient's AccountId in ss58check format
		to: String,

		/// amount to be transferred
		amount: Balance,
	},

	/// query enclave registry and list all workers
	ListWorkers,

	/// listen to parentchain events
	Listen {
		/// exit after given number of parentchain events
		#[clap(short, long = "exit-after")]
		events: Option<u32>,

		/// exit after given number of blocks
		#[clap(short, long = "await-blocks")]
		blocks: Option<u32>,
	},

	/// Transfer funds from an parentchain account to an incognito account
	ShieldFunds {
		/// Sender's parentchain AccountId in ss58check format
		from: String,

		/// Recipient's incognito AccountId in ss58check format
		to: String,

		/// Amount to be transferred
		amount: Balance,

		/// Shard identifier
		shard: String,
	},

	/// trusted calls to worker enclave
	#[clap(after_help = "stf subcommands depend on the stf crate this has been built against")]
	Trusted(TrustedArgs),

	/// Subcommands for the exchange oracle.
	#[clap(subcommand)]
	ExchangeOracle(ExchangeOracleSubCommand),
}

pub fn match_command(cli: &Cli) {
	match &cli.command {
		Commands::Balance { account } => balance(cli, account),
		Commands::NewAccount => new_account(),
		Commands::ListAccounts => list_accounts(),
		Commands::PrintMetadata => print_metadata(cli),
		Commands::PrintSgxMetadata => print_sgx_metadata(cli),
		Commands::Faucet { accounts } => faucet(cli, accounts),
		Commands::Transfer { from, to, amount } => transfer(cli, from, to, amount),
		Commands::ListWorkers => list_workers(cli),
		Commands::Listen { events, blocks } => listen(cli, events, blocks),
		Commands::ShieldFunds { from, to, amount, shard } =>
			shield_funds(cli, from, to, amount, shard),
		Commands::Trusted(trusted) => trusted_commands::match_trusted_commands(cli, trusted),
		Commands::ExchangeOracle(cmd) => cmd.run(cli),
	};
}

fn balance(cli: &Cli, account: &str) {
	let api = get_chain_api(cli);
	let accountid = get_accountid_from_str(account);
	let balance =
		if let Some(data) = api.get_account_data(&accountid).unwrap() { data.free } else { 0 };
	println!("{}", balance);
}

fn new_account() {
	let store = LocalKeystore::open(PathBuf::from(&KEYSTORE_PATH), None).unwrap();
	let key: sr25519::AppPair = store.generate().unwrap();
	drop(store);
	println!("{}", key.public().to_ss58check());
}

fn list_accounts() {
	let store = LocalKeystore::open(PathBuf::from(&KEYSTORE_PATH), None).unwrap();
	println!("sr25519 keys:");
	for pubkey in store.public_keys::<sr25519::AppPublic>().unwrap().into_iter() {
		println!("{}", pubkey.to_ss58check());
	}
	println!("ed25519 keys:");
	for pubkey in store.public_keys::<ed25519::AppPublic>().unwrap().into_iter() {
		println!("{}", pubkey.to_ss58check());
	}
	drop(store);
}

fn print_metadata(cli: &Cli) {
	let meta = get_chain_api(cli).get_metadata().unwrap();
	println!("Metadata:\n {}", Metadata::pretty_format(&meta).unwrap());
}

fn print_sgx_metadata(cli: &Cli) {
	let worker_api_direct = get_worker_api_direct(cli);
	let metadata = worker_api_direct.get_state_metadata().unwrap();
	println!("Metadata:\n {}", Metadata::pretty_format(&metadata).unwrap());
}

fn faucet(cli: &Cli, accounts: &[String]) {
	let api = get_chain_api(cli).set_signer(AccountKeyring::Alice.pair());
	let mut nonce = api.get_nonce().unwrap();
	for account in accounts {
		let to = get_accountid_from_str(account);
		#[allow(clippy::redundant_clone)]
		let xt: UncheckedExtrinsicV4<_, _> = compose_extrinsic_offline!(
			api.clone().signer.unwrap(),
			Call::Balances(BalancesCall::transfer {
				dest: GenericAddress::Id(to.clone()),
				value: PREFUNDING_AMOUNT
			}),
			api.extrinsic_params(nonce)
		);
		// send and watch extrinsic until finalized
		println!("Faucet drips to {} (Alice's nonce={})", to, nonce);
		let _blockh = api.send_extrinsic(xt.hex_encode(), XtStatus::Ready).unwrap();
		nonce += 1;
	}
}

fn transfer(cli: &Cli, from: &str, to: &str, amount: &Balance) {
	let from_account = get_pair_from_str(from);
	let to_account = get_accountid_from_str(to);
	info!("from ss58 is {}", from_account.public().to_ss58check());
	info!("to ss58 is {}", to_account.to_ss58check());
	let api = get_chain_api(cli).set_signer(sr25519_core::Pair::from(from_account));
	let xt = api.balance_transfer(GenericAddress::Id(to_account.clone()), *amount);
	let tx_hash = api.send_extrinsic(xt.hex_encode(), XtStatus::InBlock).unwrap();
	println!("[+] TrustedOperation got finalized. Hash: {:?}\n", tx_hash);
	let result = api.get_account_data(&to_account).unwrap().unwrap();
	println!("balance for {} is now {}", to_account, result.free);
}

fn list_workers(cli: &Cli) {
	let api = get_chain_api(cli);
	let wcount = api.enclave_count(None).unwrap();
	println!("number of workers registered: {}", wcount);
	for w in 1..=wcount {
		let enclave = api.enclave(w, None).unwrap();
		if enclave.is_none() {
			println!("error reading enclave data");
			continue
		};
		let enclave = enclave.unwrap();
		let timestamp =
			DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_millis(enclave.timestamp as u64));
		println!("Enclave {}", w);
		println!("   AccountId: {}", enclave.pubkey.to_ss58check());
		println!("   MRENCLAVE: {}", enclave.mr_enclave.to_base58());
		println!("   RA timestamp: {}", timestamp);
		println!("   URL: {}", enclave.url);
	}
}

fn listen(cli: &Cli, events_arg: &Option<u32>, blocks_arg: &Option<u32>) {
	println!("{:?} {:?}", events_arg, blocks_arg);
	let api = get_chain_api(cli);
	info!("Subscribing to events");
	let (events_in, events_out) = channel();
	let mut count = 0u32;
	let mut blocks = 0u32;
	api.subscribe_events(events_in).unwrap();
	loop {
		if let Some(e) = events_arg {
			if count >= *e {
				return
			}
		};
		if let Some(b) = blocks_arg {
			if blocks >= *b {
				return
			}
		};
		let event_str = events_out.recv().unwrap();
		let _unhex = Vec::from_hex(event_str).unwrap();
		let mut _er_enc = _unhex.as_slice();
		let _events = Vec::<frame_system::EventRecord<Event, Hash>>::decode(&mut _er_enc);
		blocks += 1;
		match _events {
			Ok(evts) =>
				for evr in &evts {
					println!("decoded: phase {:?} event {:?}", evr.phase, evr.event);
					match &evr.event {
						Event::Balances(be) => {
							println!(">>>>>>>>>> balances event: {:?}", be);
							match &be {
								pallet_balances::Event::Transfer { from, to, amount } => {
									println!("From: {:?}", from);
									println!("To: {:?}", to);
									println!("Value: {:?}", amount);
								},
								_ => {
									debug!("ignoring unsupported balances event");
								},
							}
						},
						Event::Teerex(ee) => {
							println!(">>>>>>>>>> integritee event: {:?}", ee);
							count += 1;
							match &ee {
								my_node_runtime::pallet_teerex::Event::AddedEnclave(
									accountid,
									url,
								) => {
									println!(
										"AddedEnclave: {:?} at url {}",
										accountid,
										String::from_utf8(url.to_vec())
											.unwrap_or_else(|_| "error".to_string())
									);
								},
								my_node_runtime::pallet_teerex::Event::RemovedEnclave(
									accountid,
								) => {
									println!("RemovedEnclave: {:?}", accountid);
								},
								my_node_runtime::pallet_teerex::Event::Forwarded(shard) => {
									println!(
										"Forwarded request for shard {}",
										shard.encode().to_base58()
									);
								},
								my_node_runtime::pallet_teerex::Event::ProcessedParentchainBlock(
									accountid,
									block_hash,
									merkle_root,
								) => {
									println!(
										"ProcessedParentchainBlock from {} with hash {:?} and merkle root {:?}",
										accountid, block_hash, merkle_root
									);
								},
								my_node_runtime::pallet_teerex::Event::ShieldFunds(
									incognito_account,
								) => {
									println!("ShieldFunds for {:?}", incognito_account);
								},
								my_node_runtime::pallet_teerex::Event::UnshieldedFunds(
									public_account,
								) => {
									println!("UnshieldFunds for {:?}", public_account);
								},
								_ => debug!("ignoring unsupported teerex event: {:?}", ee),
							}
						},
						Event::Sidechain(ee) => {
							count += 1;
							match &ee {
								my_node_runtime::pallet_sidechain::Event::ProposedSidechainBlock(
									accountid,
									block_hash,
								) => {
									println!(
										"ProposedSidechainBlock from {} with hash {:?}",
										accountid, block_hash
									);
								},
								_ => debug!("ignoring unsupported sidechain event: {:?}", ee),
							}
						},
						_ => debug!("ignoring unsupported module event: {:?}", evr.event),
					}
				},
			Err(_) => error!("couldn't decode event record list"),
		}
	}
}

fn shield_funds(cli: &Cli, arg_from: &str, arg_to: &str, amount: &Balance, shard: &str) {
	let chain_api = get_chain_api(cli);

	let shard_opt = match shard.from_base58() {
		Ok(s) => ShardIdentifier::decode(&mut &s[..]),
		_ => panic!("shard argument must be base58 encoded"),
	};

	let shard = match shard_opt {
		Ok(shard) => shard,
		Err(e) => panic!("{}", e),
	};

	// get the sender
	let from = get_pair_from_str(arg_from);
	let chain_api = chain_api.set_signer(sr25519_core::Pair::from(from));

	// get the recipient
	let to = get_accountid_from_str(arg_to);

	let encryption_key = get_shielding_key(cli).unwrap();
	let encrypted_recevier = encryption_key.encrypt(&to.encode()).unwrap();

	// compose the extrinsic
	let xt: UncheckedExtrinsicV4<_, _> =
		compose_extrinsic!(chain_api, TEEREX, "shield_funds", encrypted_recevier, *amount, shard);

	let tx_hash = chain_api.send_extrinsic(xt.hex_encode(), XtStatus::Finalized).unwrap();
	println!("[+] TrustedOperation got finalized. Hash: {:?}\n", tx_hash);
}
