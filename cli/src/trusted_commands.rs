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
	command_utils::get_worker_api_direct,
	trusted_command_utils::{
		get_accountid_from_str, get_identifiers, get_keystore_path, get_pair_from_str,
	},
	trusted_operation::{
		initialize_receiver_for_direct_request, perform_trusted_operation, wait_until,
	},
	Cli,
};
use codec::Decode;
use hdrhistogram::Histogram;
use ita_stf::{Index, KeyPair, TrustedCall, TrustedGetter, TrustedOperation};
use itc_rpc_client::direct_client::DirectApi;
use itp_types::{
	TrustedOperationStatus,
	TrustedOperationStatus::{InSidechainBlock, Submitted},
};
use log::*;
use my_node_runtime::Balance;
use rayon::prelude::*;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sp_application_crypto::{ed25519, sr25519};
use sp_core::{crypto::Ss58Codec, sr25519 as sr25519_core, Pair};
use std::{
	collections::HashMap,
	fs::File,
	io::{BufWriter, Write},
	time::Instant,
};
use substrate_client_keystore::{KeystoreExt, LocalKeystore};

macro_rules! get_layer_two_nonce {
	($signer_pair:ident, $cli: ident, $trusted_args:ident ) => {{
		let top: TrustedOperation =
			TrustedGetter::nonce(sr25519_core::Public::from($signer_pair.public()).into())
				.sign(&KeyPair::Sr25519($signer_pair.clone()))
				.into();
		let res = perform_operation($cli, $trusted_args, &top);
		let nonce: Index = if let Some(n) = res {
			if let Ok(nonce) = Index::decode(&mut n.as_slice()) {
				nonce
			} else {
				0
			}
		} else {
			0
		};
		debug!("got layer two nonce: {:?}", nonce);
		nonce
	}};
}

#[derive(Args)]
pub struct TrustedArgs {
	/// targeted worker MRENCLAVE
	#[clap(short, long)]
	pub(crate) mrenclave: String,

	/// shard identifier
	#[clap(short, long)]
	pub(crate) shard: Option<String>,

	/// signer for publicly observable extrinsic
	#[clap(short='a', long, default_value_t = String::from("//Alice"))]
	pub(crate) xt_signer: String,

	/// insert if direct invocation call is desired
	#[clap(short, long)]
	direct: bool,

	#[clap(subcommand)]
	command: TrustedCommands,
}

#[derive(Subcommand)]
pub enum TrustedCommands {
	/// generates a new incognito account for the given shard
	NewAccount,

	/// lists all incognito accounts in a given shard
	ListAccounts,

	/// send funds from one incognito account to another
	Transfer {
		/// sender's AccountId in ss58check format
		from: String,

		/// recipient's AccountId in ss58check format
		to: String,

		/// amount to be transferred
		amount: Balance,
	},

	/// ROOT call to set some account balance to an arbitrary number
	SetBalance {
		/// sender's AccountId in ss58check format
		account: String,

		/// amount to be transferred
		amount: Balance,
	},

	/// query balance for incognito account in keystore
	Balance {
		/// AccountId in ss58check format
		account: String,
	},

	/// Transfer funds from an incognito account to an parentchain account
	UnshieldFunds {
		/// Sender's incognito AccountId in ss58check format
		from: String,

		/// Recipient's parentchain AccountId in ss58check format
		to: String,

		/// amount to be transferred
		amount: Balance,
	},

	/// Run Benchmark
	Benchmark,
}

pub fn match_trusted_commands(cli: &Cli, trusted_args: &TrustedArgs) {
	match &trusted_args.command {
		TrustedCommands::NewAccount => new_account(trusted_args),
		TrustedCommands::ListAccounts => list_accounts(trusted_args),
		TrustedCommands::Transfer { from, to, amount } =>
			transfer(cli, trusted_args, from, to, amount),
		TrustedCommands::SetBalance { account, amount } =>
			set_balance(cli, trusted_args, account, amount),
		TrustedCommands::Balance { account } => balance(cli, trusted_args, account),
		TrustedCommands::UnshieldFunds { from, to, amount } =>
			unshield_funds(cli, trusted_args, from, to, amount),
		TrustedCommands::Benchmark => transfer_benchmark(cli, trusted_args),
	}
}

fn perform_operation(
	cli: &Cli,
	trusted_args: &TrustedArgs,
	top: &TrustedOperation,
) -> Option<Vec<u8>> {
	perform_trusted_operation(cli, trusted_args, top)
}

fn new_account(trusted_args: &TrustedArgs) {
	let store = LocalKeystore::open(get_keystore_path(trusted_args), None).unwrap();
	let key: sr25519::AppPair = store.generate().unwrap();
	drop(store);
	println!("{}", key.public().to_ss58check());
}

fn list_accounts(trusted_args: &TrustedArgs) {
	let store = LocalKeystore::open(get_keystore_path(trusted_args), None).unwrap();
	info!("sr25519 keys:");
	for pubkey in store.public_keys::<sr25519::AppPublic>().unwrap().into_iter() {
		println!("{}", pubkey.to_ss58check());
	}
	info!("ed25519 keys:");
	for pubkey in store.public_keys::<ed25519::AppPublic>().unwrap().into_iter() {
		println!("{}", pubkey.to_ss58check());
	}
	drop(store);
}

fn transfer(cli: &Cli, trusted_args: &TrustedArgs, arg_from: &str, arg_to: &str, amount: &Balance) {
	let from = get_pair_from_str(trusted_args, arg_from);
	let to = get_accountid_from_str(arg_to);
	info!("from ss58 is {}", from.public().to_ss58check());
	info!("to ss58 is {}", to.to_ss58check());

	println!("send trusted call transfer from {} to {}: {}", from.public(), to, amount);
	let (mrenclave, shard) = get_identifiers(trusted_args);
	let nonce = get_layer_two_nonce!(from, cli, trusted_args);
	let top: TrustedOperation = TrustedCall::balance_transfer(from.public().into(), to, *amount)
		.sign(&KeyPair::Sr25519(from), nonce, &mrenclave, &shard)
		.into_trusted_operation(trusted_args.direct);
	let _ = perform_operation(cli, trusted_args, &top);
}

struct BenchmarkClient {
	account1: sr25519_core::Pair,
	account2: sr25519_core::Pair,
}

fn transfer_benchmark(cli: &Cli, trusted_args: &TrustedArgs) {
	let alice = get_pair_from_str(trusted_args, "//Alice");

	let (mrenclave, shard) = get_identifiers(trusted_args);

	// get shielding pubkey
	let worker_api_direct = get_worker_api_direct(cli);
	let shielding_pubkey: Rsa3072PubKey = match worker_api_direct.get_rsa_pubkey() {
		Ok(key) => key,
		Err(err_msg) => panic!("{}", err_msg.to_string()),
	};

	let mut accounts = Vec::new();

	let num_threads = 30;
	for i in 0..num_threads {
		let nonce_alice = i * 2;
		println!("Initialization {}", i);

		// create new accounts to use
		let store = LocalKeystore::open(get_keystore_path(trusted_args), None).unwrap();
		let a1: sr25519::AppPair = store.generate().unwrap();
		let a2: sr25519::AppPair = store.generate().unwrap();
		let account1 = get_pair_from_str(trusted_args, a1.public().to_string().as_str());
		let account2 = get_pair_from_str(trusted_args, a2.public().to_string().as_str());
		let client = BenchmarkClient { account1, account2 };
		drop(store);

		// transfer amount from Alice to new accounts
		let top: TrustedOperation =
			TrustedCall::balance_transfer(alice.public().into(), client.account1.public().into(), 100000)
				.sign(&KeyPair::Sr25519(alice.clone()), nonce_alice, &mrenclave, &shard)
				.into_trusted_operation(trusted_args.direct);

		let results = run_transaction(cli, trusted_args, shielding_pubkey, top, true, &client);

		if results.iter().any(|r| r.0 == "InSidechainBlock") {
			println!("initialization of new account1 successfull");
		} else {
			println!("initialization of new account1 NOT successfull");
		}

		let top2: TrustedOperation =
			TrustedCall::balance_transfer(alice.public().into(), client.account2.public().into(), 100000)
				.sign(&KeyPair::Sr25519(alice.clone()), nonce_alice + 1, &mrenclave, &shard)
				.into_trusted_operation(trusted_args.direct);

		let results2 = run_transaction(cli, trusted_args, shielding_pubkey, top2, true, &client);

		if results2.iter().any(|r| r.0 == "InSidechainBlock") {
			println!("initialization of new account2 successfull");
		} else {
			println!("initialization of new account2 NOT successfull");
		}

		println!("account1 is {}", client.account1.public());
		println!("account2 is {}", client.account2.public());

		accounts.push(client);
	}

	let proc_info = procfs::process::Process::myself().unwrap();
	let max_fds = proc_info.limits().unwrap().max_open_files;
	println!("Max fds: {:?}/{:?}", max_fds.soft_limit, max_fds.hard_limit);
	let overall_start = Instant::now();

	rayon::ThreadPoolBuilder::new().num_threads(num_threads as usize).build_global().unwrap();

	let outputs: Vec<(Vec<String>, Vec<u128>)> = accounts
		.into_par_iter()
		.map(| client| {
			let mut output: Vec<String> = Vec::new();
			let mut in_sidechain_block_timestamps = Vec::new();

			for nonce in 0..30 {
				let number_fd = proc_info.fd_count().unwrap();
				let threads = proc_info.status().unwrap().threads;
				println!("#fd: {}, #threads: {}", number_fd, threads);
				//account1 -> account2
				let top: TrustedOperation = TrustedCall::balance_transfer(
					client.account1.public().into(),
					client.account2.public().into(),
					50000,
				)
				.sign(&KeyPair::Sr25519(client.account1.clone()), nonce, &mrenclave, &shard)
				.into_trusted_operation(trusted_args.direct);

				let start_time = Instant::now();
				let results = run_transaction(cli, trusted_args, shielding_pubkey, top, true, &client);
				for (key, value) in results {
					output.push(format!(
						"{}: {}",
						key,
						value.duration_since(start_time).as_millis()
					));
					if key == "InSidechainBlock" {
						in_sidechain_block_timestamps
							.push(value.duration_since(start_time).as_millis());
					}
				}

				//account2 -> account1
				let top2: TrustedOperation = TrustedCall::balance_transfer(
					client.account2.public().into(),
					client.account1.public().into(),
					50000,
				)
				.sign(&KeyPair::Sr25519(client.account2.clone()), nonce, &mrenclave, &shard)
				.into_trusted_operation(trusted_args.direct);

				let start_time2 = Instant::now();
				let results2 = run_transaction(cli, trusted_args, shielding_pubkey, top2, true, &client);
				for (key, value) in results2 {
					output.push(format!(
						"{}: {}",
						key,
						value.duration_since(start_time2).as_millis()
					));
					if key == "InSidechainBlock" {
						in_sidechain_block_timestamps
							.push(value.duration_since(start_time2).as_millis());
					}
				}
			}

			(output, in_sidechain_block_timestamps)
		})
		.collect();


	println!("Time for transactions: {}", overall_start.elapsed().as_secs());
	let file = File::create(format!(
		"benchmark_{}.txt",
		chrono::offset::Local::now().format("%Y-%m-%d_%H_%M")
	))
	.expect("unable to create file");
	let mut file = BufWriter::new(file);

	let mut hist = Histogram::<u64>::new(1).unwrap();
	println!("Size of outputs: {}", outputs.len());
	for output in outputs {
		for t in output.1 {
			hist += t as u64;
		}
	}

	println!("Samples recorded: {}", hist.len());
	for v in hist.iter_recorded() {
		let text = format!(
			"{}'th percentile of data is {} with {} samples",
			v.percentile(),
			v.value_iterated_to(),
			v.count_at_value()
		);
		writeln!(file, "{}", text).expect("cannot write to file");
		println!("{}", text);
	}
}

fn run_transaction(
	cli: &Cli,
	trusted_args: &TrustedArgs,
	shielding_pubkey: Rsa3072PubKey,
	top: TrustedOperation,
	wait_for_sidechain_block: bool,
	client: &BenchmarkClient,
) -> Vec<(String, Instant)> {
	let mut timestamps = Vec::new();

	let (direct_api, receiver) = match top {
		TrustedOperation::direct_call(call) => initialize_receiver_for_direct_request(
			cli,
			trusted_args,
			TrustedOperation::direct_call(call),
			shielding_pubkey,
		),
		_ => (None, None),
	};

	if let Some(r) = receiver {

		if let Some(t) = wait_until(&r, is_submitted) {
			timestamps.push(("Submitted".to_string(), t))
		}

		if wait_for_sidechain_block {
			if let Some(t) = wait_until(&r, is_sidechain_block) {
				timestamps.push(("InSidechainBlock".to_string(), t))
			}
		}
	};
	if let Some(api) = direct_api {
		api.close();
	}

	timestamps
}

fn is_submitted(s: TrustedOperationStatus) -> bool {
	matches!(s, Submitted)
}

fn is_sidechain_block(s: TrustedOperationStatus) -> bool {
	matches!(s, InSidechainBlock(_))
}

fn set_balance(cli: &Cli, trusted_args: &TrustedArgs, arg_who: &str, amount: &Balance) {
	let who = get_pair_from_str(trusted_args, arg_who);
	let signer = get_pair_from_str(trusted_args, "//Alice");
	info!("account ss58 is {}", who.public().to_ss58check());

	println!("send trusted call set-balance({}, {})", who.public(), amount);

	let (mrenclave, shard) = get_identifiers(trusted_args);
	let nonce = get_layer_two_nonce!(signer, cli, trusted_args);
	let top: TrustedOperation = TrustedCall::balance_set_balance(
		signer.public().into(),
		who.public().into(),
		*amount,
		*amount,
	)
	.sign(&KeyPair::Sr25519(signer), nonce, &mrenclave, &shard)
	.into_trusted_operation(trusted_args.direct);
	let _ = perform_operation(cli, trusted_args, &top);
}

fn balance(cli: &Cli, trusted_args: &TrustedArgs, arg_who: &str) {
	debug!("arg_who = {:?}", arg_who);
	let who = get_pair_from_str(trusted_args, arg_who);
	let top: TrustedOperation = TrustedGetter::free_balance(who.public().into())
		.sign(&KeyPair::Sr25519(who))
		.into();
	let res = perform_operation(cli, trusted_args, &top);
	debug!("received result for balance");
	let bal = if let Some(v) = res {
		if let Ok(vd) = Balance::decode(&mut v.as_slice()) {
			vd
		} else {
			info!("could not decode value. maybe hasn't been set? {:x?}", v);
			0
		}
	} else {
		0
	};
	println!("{}", bal);
}

fn unshield_funds(
	cli: &Cli,
	trusted_args: &TrustedArgs,
	arg_from: &str,
	arg_to: &str,
	amount: &Balance,
) {
	let from = get_pair_from_str(trusted_args, arg_from);
	let to = get_accountid_from_str(arg_to);
	println!("from ss58 is {}", from.public().to_ss58check());
	println!("to   ss58 is {}", to.to_ss58check());

	println!("send trusted call unshield_funds from {} to {}: {}", from.public(), to, amount);

	let (mrenclave, shard) = get_identifiers(trusted_args);
	let nonce = get_layer_two_nonce!(from, cli, trusted_args);
	let top: TrustedOperation =
		TrustedCall::balance_unshield(from.public().into(), to, *amount, shard)
			.sign(&KeyPair::Sr25519(from), nonce, &mrenclave, &shard)
			.into_trusted_operation(trusted_args.direct);
	let _ = perform_operation(cli, trusted_args, &top);
}
