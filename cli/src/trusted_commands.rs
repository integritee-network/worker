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
	trusted_operation::{get_json_request, perform_trusted_operation, read_shard, wait_until},
	Cli,
};
use codec::Decode;
use hdrhistogram::Histogram;
use ita_stf::{Index, KeyPair, TrustedCall, TrustedGetter, TrustedOperation};
use itc_rpc_client::direct_client::{DirectApi, DirectClient};
use itp_types::{
	TrustedOperationStatus,
	TrustedOperationStatus::{InSidechainBlock, Submitted},
};
use log::*;
use my_node_runtime::Balance;
use rand::Rng;
use rayon::prelude::*;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sp_application_crypto::{ed25519, sr25519};
use sp_core::{crypto::Ss58Codec, sr25519 as sr25519_core, Pair};
use std::{
	string::ToString,
	sync::mpsc::{channel, Receiver},
	thread, time,
	time::Instant,
	vec::Vec,
};
use substrate_client_keystore::{KeystoreExt, LocalKeystore};

#[cfg(feature = "evm")]
use sp_runtime::traits::BlakeTwo256;

#[cfg(feature = "evm")]
use pallet_evm::{AddressMapping, HashedAddressMapping};

#[cfg(feature = "evm")]
use itp_types::AccountId;

#[cfg(feature = "evm")]
use ita_stf::evm_helpers::evm_create_address;

#[cfg(feature = "evm")]
use substrate_api_client::utils::FromHexString;

#[cfg(feature = "evm")]
use sp_core::{H160, H256, U256};

macro_rules! get_layer_two_nonce {
	($signer_pair:ident, $cli: ident, $trusted_args:ident ) => {{
		let top: TrustedOperation = TrustedGetter::nonce($signer_pair.public().into())
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

#[cfg(feature = "evm")]
macro_rules! get_layer_two_evm_nonce {
	($signer_pair:ident, $cli:ident, $trusted_args:ident ) => {{
		let top: TrustedOperation = TrustedGetter::evm_nonce($signer_pair.public().into())
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

	#[cfg(feature = "evm")]
	/// Create smart contract
	EvmCreate {
		/// Sender's incognito AccountId in ss58check format
		from: String,

		/// Smart Contract in Hex format
		smart_contract: String,
	},

	#[cfg(feature = "evm")]
	/// Read smart contract storage
	EvmRead {
		/// Sender's incognito AccountId in ss58check format
		from: String,

		/// Execution address of the smart contract
		execution_address: String,
	},

	#[cfg(feature = "evm")]
	/// Create smart contract
	EvmCall {
		/// Sender's incognito AccountId in ss58check format
		from: String,

		/// Execution address of the smart contract
		execution_address: String,

		/// Function hash
		function: String,
	},

	/// Run Benchmark
	Benchmark {
		/// The number of clients (=threads) to be used in the benchmark
		#[clap(default_value_t = 10)]
		number_clients: u32,

		/// The number of iterations to execute for each client
		#[clap(default_value_t = 30)]
		number_iterations: u32,

		/// Adds a random wait before each transaction. This is the lower bound for the interval in ms.
		#[clap(default_value_t = 0)]
		random_wait_before_transaction_min_ms: u32,

		/// Adds a random wait before each transaction. This is the upper bound for the interval in ms.
		#[clap(default_value_t = 0)]
		random_wait_before_transaction_max_ms: u32,

		/// Whether to wait for "InSidechainBlock" confirmation for each transaction
		#[clap(short, long)]
		wait_for_confirmation: bool,

		/// Account to be used for initial funding of generated accounts used in benchmark
		#[clap(default_value_t = String::from("//Alice"))]
		funding_account: String,
	},
}

pub fn match_trusted_commands(cli: &Cli, trusted_args: &TrustedArgs) {
	match &trusted_args.command {
		TrustedCommands::NewAccount => new_account(trusted_args),
		TrustedCommands::ListAccounts => list_accounts(trusted_args),
		TrustedCommands::Transfer { from, to, amount } =>
			transfer(cli, trusted_args, from, to, amount),
		TrustedCommands::SetBalance { account, amount } =>
			set_balance(cli, trusted_args, account, amount),
		TrustedCommands::Balance { account } => print_balance(cli, trusted_args, account),
		TrustedCommands::UnshieldFunds { from, to, amount } =>
			unshield_funds(cli, trusted_args, from, to, amount),
		TrustedCommands::Benchmark {
			number_clients,
			number_iterations,
			random_wait_before_transaction_min_ms,
			random_wait_before_transaction_max_ms,
			wait_for_confirmation,
			funding_account,
		} => transfer_benchmark_increasing_nonce(
			cli,
			trusted_args,
			*number_clients,
			*number_iterations,
			(*random_wait_before_transaction_min_ms, *random_wait_before_transaction_max_ms),
			*wait_for_confirmation,
			funding_account,
		),
		#[cfg(feature = "evm")]
		TrustedCommands::EvmCreate { from, smart_contract } =>
			evm_create(cli, trusted_args, from, smart_contract),
		#[cfg(feature = "evm")]
		TrustedCommands::EvmRead { from, execution_address } =>
			evm_read_storage(cli, trusted_args, from, execution_address),
		#[cfg(feature = "evm")]
		TrustedCommands::EvmCall { from, execution_address, function } =>
			evm_call(cli, trusted_args, from, execution_address, function),
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
	info!("new account {}", key.public().to_ss58check());
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
	info!("trusted call transfer executed");
}

struct BenchmarkClient {
	account: sr25519_core::Pair,
	current_balance: u128,
	client_api: DirectClient,
	receiver: Receiver<String>,
}

impl BenchmarkClient {
	fn new(
		account: sr25519_core::Pair,
		initial_balance: u128,
		initial_request: String,
		cli: &Cli,
	) -> Self {
		debug!("get direct api");
		let client_api = get_worker_api_direct(cli);

		debug!("setup sender and receiver");
		let (sender, receiver) = channel();
		client_api.watch(initial_request, sender);
		BenchmarkClient { account, current_balance: initial_balance, client_api, receiver }
	}
}

/// Stores timing information about a specific transaction
struct BenchmarkTransaction {
	started: Instant,
	submitted: Instant,
	confirmed: Option<Instant>,
}

fn transfer_benchmark_increasing_state(
	cli: &Cli,
	trusted_args: &TrustedArgs,
	number_clients: u32,
	number_iterations: u32,
	random_wait_before_transaction_ms: (u32, u32),
	wait_for_confirmation: bool,
	funding_account: &str,
) {
	let shard = read_shard(trusted_args).unwrap();
	let store = LocalKeystore::open(get_keystore_path(trusted_args), None).unwrap();
	let funding_account_keys = get_pair_from_str(trusted_args, funding_account);

	let (mrenclave, shard) = get_identifiers(trusted_args);

	// Get shielding pubkey.
	let worker_api_direct = get_worker_api_direct(cli);
	let shielding_pubkey: Rsa3072PubKey = match worker_api_direct.get_rsa_pubkey() {
		Ok(key) => key,
		Err(err_msg) => panic!("{}", err_msg.to_string()),
	};

	let nonce_start = get_layer_two_nonce!(funding_account_keys, cli, trusted_args);
	println!("Nonce for account {}: {}", funding_account, nonce_start);

	let mut accounts = Vec::new();

	// Setup new accounts and initialize them with money from Alice.
	for i in 0..number_clients {
		let nonce = i + nonce_start;
		println!("Initializing account {}", i);

		// Create new account to use.
		let a: sr25519::AppPair = store.generate().unwrap();
		let account = get_pair_from_str(trusted_args, a.public().to_string().as_str());
		let initial_balance = 10000000;

		// Transfer amount from Alice to new account.
		let top: TrustedOperation = TrustedCall::balance_transfer(
			funding_account_keys.public().into(),
			account.public().into(),
			initial_balance,
		)
		.sign(&KeyPair::Sr25519(funding_account_keys.clone()), nonce, &mrenclave, &shard)
		.into_trusted_operation(trusted_args.direct);

		// For the last account we wait for confirmation in order to ensure all accounts were setup correctly
		let wait_for_confirmation = i == number_clients - 1;
		let account_funding_request = get_json_request(shard, &top, shielding_pubkey);

		let client = BenchmarkClient::new(account, initial_balance, account_funding_request, cli);
		let _result = wait_for_top_confirmation(wait_for_confirmation, &client);
		accounts.push(client);
	}

	rayon::ThreadPoolBuilder::new()
		.num_threads(number_clients as usize)
		.build_global()
		.unwrap();

	let overall_start = Instant::now();

	// Run actual benchmark logic, in parallel, for each account initialized above.
	let outputs: Vec<Vec<BenchmarkTransaction>> = accounts
		.into_par_iter()
		.map(move |mut client| {
			let mut output: Vec<BenchmarkTransaction> = Vec::new();

			for i in 0..number_iterations {
				println!("Iteration: {}", i);

				if random_wait_before_transaction_ms.1 > 0 {
					random_wait(random_wait_before_transaction_ms);
				}

				let nonce = 0;

				// Create new account.
				let account_keys: sr25519::AppPair = store.generate().unwrap();
				let new_account =
					get_pair_from_str(trusted_args, account_keys.public().to_string().as_str());

				println!("  Transfer amount: {}", client.current_balance);
				println!("  From: {:?}", client.account.public());
				println!("  To:   {:?}", new_account.public());

				// The account from the last iteration keeps this much money.
				// If this is 0, then all money is transferred and the state doesn't increase.
				let keep_alive_balance = 1000;

				// Transfer money from previous account to new account.
				let top: TrustedOperation = TrustedCall::balance_transfer(
					client.account.public().into(),
					new_account.public().into(),
					client.current_balance - keep_alive_balance,
				)
				.sign(&KeyPair::Sr25519(client.account.clone()), nonce, &mrenclave, &shard)
				.into_trusted_operation(trusted_args.direct);

				let last_iteration = i == number_iterations - 1;
				let jsonrpc_call = get_json_request(shard, &top, shielding_pubkey);
				client.client_api.send(&jsonrpc_call).unwrap();
				let result =
					wait_for_top_confirmation(wait_for_confirmation || last_iteration, &client);

				client.current_balance -= keep_alive_balance;
				client.account = new_account;

				output.push(result);
			}
			client.client_api.close().unwrap();

			let balance = get_balance(cli, trusted_args, &client.account.public().to_string());
			println!("Balance: {}", balance.unwrap_or_default());
			assert_eq!(client.current_balance, balance.unwrap());

			output
		})
		.collect();

	println!(
		"Finished benchmark with {} clients and {} transactions in {} ms",
		number_clients,
		number_iterations,
		overall_start.elapsed().as_millis()
	);

	print_benchmark_statistic(outputs, wait_for_confirmation)
}

fn transfer_benchmark_increasing_nonce(
	cli: &Cli,
	trusted_args: &TrustedArgs,
	number_clients: u32,
	number_iterations: u32,
	random_wait_before_transaction_ms: (u32, u32),
	wait_for_confirmation: bool,
	funding_account: &str,
) {
	let shard = read_shard(trusted_args).unwrap();
	let store = LocalKeystore::open(get_keystore_path(trusted_args), None).unwrap();
	let funding_account_keys = get_pair_from_str(trusted_args, funding_account);

	let (mrenclave, shard) = get_identifiers(trusted_args);

	// Get shielding pubkey.
	let worker_api_direct = get_worker_api_direct(cli);
	let shielding_pubkey: Rsa3072PubKey = match worker_api_direct.get_rsa_pubkey() {
		Ok(key) => key,
		Err(err_msg) => panic!("{}", err_msg.to_string()),
	};

	let nonce_start = get_layer_two_nonce!(funding_account_keys, cli, trusted_args);
	println!("Nonce for account {}: {}", funding_account, nonce_start);

	let mut accounts = Vec::new();

	// Setup new accounts and initialize them with money from Alice.
	for i in 0..number_clients {
		let nonce = i + nonce_start;
		println!("Initializing account {}", i);

		// Create new account to use.
		let a: sr25519::AppPair = store.generate().unwrap();
		let account = get_pair_from_str(trusted_args, a.public().to_string().as_str());
		let initial_balance = 10000000;

		// Transfer amount from Alice to new account.
		let top: TrustedOperation = TrustedCall::balance_transfer(
			funding_account_keys.public().into(),
			account.public().into(),
			initial_balance,
		)
		.sign(&KeyPair::Sr25519(funding_account_keys.clone()), nonce, &mrenclave, &shard)
		.into_trusted_operation(trusted_args.direct);

		// For the last account we wait for confirmation in order to ensure all accounts were setup correctly
		let wait_for_confirmation = i == number_clients - 1;
		let account_funding_request = get_json_request(shard.clone(), &top, shielding_pubkey);

		let client = BenchmarkClient::new(account, initial_balance, account_funding_request, cli);
		let _result = wait_for_top_confirmation(wait_for_confirmation, &client);
		accounts.push(client);
	}

	rayon::ThreadPoolBuilder::new()
		.num_threads(number_clients as usize)
		.build_global()
		.unwrap();

	let overall_start = Instant::now();

	// Run actual benchmark logic, in parallel, for each account initialized above.
	let outputs: Vec<Vec<BenchmarkTransaction>> = accounts
		.into_par_iter()
		.map(move |mut client| {
			let mut output: Vec<BenchmarkTransaction> = Vec::new();

			for i in 0..number_iterations {
				println!("Iteration: {}", i);

				if random_wait_before_transaction_ms.1 > 0 {
					random_wait(random_wait_before_transaction_ms);
				}
				// Create new account.
				let account_keys: sr25519::AppPair = store.generate().unwrap();
				let new_account =
					get_pair_from_str(trusted_args, account_keys.public().to_string().as_str());

				// The new account gets this amount of money. Needs to be above the
				// existential deposit, otherwise the new account will not be generated.
				let transfer_amount = 1000;
				println!("  Transfer amount: {}", transfer_amount);
				println!("  From: {:?}", client.account.public());
				println!("  To:   {:?}", new_account.public());

				let account_pair = client.account.clone();
				// Get nonce of account
				let nonce_top: TrustedOperation =
					TrustedGetter::nonce(account_pair.public().into())
						.sign(&KeyPair::Sr25519(account_pair.clone()))
						.into();

				let jsonrpc_call = get_json_request(shard, &nonce_top, shielding_pubkey);

				let start_time = Instant::now();
				let nonce = get_layer_two_nonce!(account_pair, cli, trusted_args);
				let elapsed_seconds = start_time.elapsed().as_secs();
				if elapsed_seconds > 10 {
					println!(
						"!!!!! [Error]: Running Nonce getter took {} seconds",
						elapsed_seconds
					);
				}

				// Transfer money to new account.
				let top: TrustedOperation = TrustedCall::balance_transfer(
					client.account.public().into(),
					new_account.public().into(),
					transfer_amount,
				)
				.sign(&KeyPair::Sr25519(client.account.clone()), nonce, &mrenclave, &shard)
				.into_trusted_operation(trusted_args.direct);

				let last_iteration = i == number_iterations - 1;
				let jsonrpc_call = get_json_request(shard, &top, shielding_pubkey);
				client.client_api.send(&jsonrpc_call).unwrap();
				let start_time = Instant::now();
				let result =
					wait_for_top_confirmation(wait_for_confirmation || last_iteration, &client);
				let elapsed_seconds = start_time.elapsed().as_secs();
				if elapsed_seconds > 10 {
					println!(
						"!!!!! [Error]: Running Transfer call took {} seconds",
						elapsed_seconds
					);
				}

				let start_time = Instant::now();

				client.current_balance =
					get_balance(cli, trusted_args, &client.account.public().to_string()).unwrap();
				let elapsed_seconds = start_time.elapsed().as_secs();
				if elapsed_seconds > 10 {
					println!(
						"!!!!! [Error]: Running balance getter took {} seconds",
						elapsed_seconds
					);
				}

				output.push(result);
			}
			client.client_api.close().unwrap();

			let balance = get_balance(cli, trusted_args, &client.account.public().to_string());
			println!("Balance: {}", balance.unwrap_or_default());
			assert_eq!(client.current_balance, balance.unwrap());

			output
		})
		.collect();

	println!(
		"Finished benchmark with {} clients and {} transactions in {} ms",
		number_clients,
		number_iterations,
		overall_start.elapsed().as_millis()
	);

	print_benchmark_statistic(outputs, wait_for_confirmation)
}

fn print_benchmark_statistic(outputs: Vec<Vec<BenchmarkTransaction>>, wait_for_confirmation: bool) {
	let mut hist = Histogram::<u64>::new(1).unwrap();
	for output in outputs {
		for t in output {
			let benchmarked_timestamp =
				if wait_for_confirmation { t.confirmed } else { Some(t.submitted) };
			if let Some(confirmed) = benchmarked_timestamp {
				hist += confirmed.duration_since(t.started).as_millis() as u64;
			} else {
				println!("Missing measurement data");
			}
		}
	}

	for i in (5..=100).step_by(5) {
		let text = format!(
			"{} percent are done within {} ms",
			i,
			hist.value_at_quantile(i as f64 / 100.0)
		);
		println!("{}", text);
	}
}

fn random_wait(random_wait_before_transaction_ms: (u32, u32)) {
	let mut rng = rand::thread_rng();
	let sleep_time = time::Duration::from_millis(
		rng.gen_range(random_wait_before_transaction_ms.0..=random_wait_before_transaction_ms.1)
			.into(),
	);
	println!("Sleep for: {}ms", sleep_time.as_millis());
	thread::sleep(sleep_time);
}

fn wait_for_top_confirmation(
	wait_for_sidechain_block: bool,
	client: &BenchmarkClient,
) -> BenchmarkTransaction {
	let started = Instant::now();

	let submitted = wait_until(&client.receiver, is_submitted);

	let confirmed = if wait_for_sidechain_block {
		// We wait for the transaction hash that actually matches the submitted hash
		loop {
			let transaction_information = wait_until(&client.receiver, is_sidechain_block);
			if let Some((hash, _)) = transaction_information {
				if hash == submitted.unwrap().0 {
					break transaction_information
				}
			}
		}
	} else {
		None
	};
	if let (Some(s), Some(c)) = (submitted, confirmed) {
		// Assert the two hashes are identical
		assert_eq!(s.0, c.0);
	}

	BenchmarkTransaction {
		started,
		submitted: submitted.unwrap().1,
		confirmed: confirmed.map(|v| v.1),
	}
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

fn print_balance(cli: &Cli, trusted_args: &TrustedArgs, arg_who: &str) {
	println!("{}", get_balance(cli, trusted_args, arg_who).unwrap_or_default());
}

fn get_balance(cli: &Cli, trusted_args: &TrustedArgs, arg_who: &str) -> Option<u128> {
	debug!("arg_who = {:?}", arg_who);
	let who = get_pair_from_str(trusted_args, arg_who);
	let top: TrustedOperation = TrustedGetter::free_balance(who.public().into())
		.sign(&KeyPair::Sr25519(who))
		.into();
	let res = perform_operation(cli, trusted_args, &top);
	debug!("received result for balance");
	let bal = if let Some(v) = res {
		if let Ok(vd) = Balance::decode(&mut v.as_slice()) {
			Some(vd)
		} else {
			info!("could not decode value. maybe hasn't been set? {:x?}", v);
			None
		}
	} else {
		None
	};
	bal
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

#[cfg(feature = "evm")]
fn evm_create(cli: &Cli, trusted_args: &TrustedArgs, arg_from: &str, smart_contract: &str) {
	let from = get_pair_from_str(trusted_args, arg_from);
	let from_acc: AccountId = from.public().into();
	println!("from ss58 is {}", from.public().to_ss58check());

	let mut sender_evm_acc_slice: [u8; 20] = [0; 20];
	sender_evm_acc_slice.copy_from_slice((<[u8; 32]>::from(from_acc.clone())).get(0..20).unwrap());
	let sender_evm_acc: H160 = sender_evm_acc_slice.into();

	let (mrenclave, shard) = get_identifiers(trusted_args);

	let sender_evm_substrate_addr =
		HashedAddressMapping::<BlakeTwo256>::into_account_id(sender_evm_acc);
	println!("Trying to get nonce of evm account {:?}", sender_evm_substrate_addr.to_ss58check());

	let nonce = get_layer_two_nonce!(from, cli, trusted_args);
	let evm_account_nonce = get_layer_two_evm_nonce!(from, cli, trusted_args);

	let top = TrustedCall::evm_create(
		from_acc,
		sender_evm_acc,
		Vec::from_hex(smart_contract.to_string()).unwrap(),
		U256::from(0),
		967295,        // gas limit
		U256::from(1), // max_fee_per_gas !>= min_gas_price defined in runtime
		None,
		None,
		Vec::new(),
	)
	.sign(&from.into(), nonce, &mrenclave, &shard)
	.into_trusted_operation(trusted_args.direct);

	let _ = perform_operation(cli, trusted_args, &top);

	let execution_address = evm_create_address(sender_evm_acc, evm_account_nonce);
	info!("trusted call evm_create executed");
	println!("Created the smart contract with address {:?}", execution_address);
}

#[cfg(feature = "evm")]
fn evm_read_storage(
	cli: &Cli,
	trusted_args: &TrustedArgs,
	arg_from: &str,
	execution_address_str: &str,
) {
	let sender = get_pair_from_str(trusted_args, arg_from);
	let sender_acc: AccountId = sender.public().into();

	println!("senders ss58 is {}", sender.public().to_ss58check());

	let mut sender_evm_acc_slice: [u8; 20] = [0; 20];
	sender_evm_acc_slice
		.copy_from_slice((<[u8; 32]>::from(sender_acc.clone())).get(0..20).unwrap());
	let sender_evm_acc: H160 = sender_evm_acc_slice.into();

	println!("senders evm account is {}", sender_evm_acc);

	let execution_address =
		H160::from_slice(&Vec::from_hex(execution_address_str.to_string()).unwrap());

	let top: TrustedOperation =
		TrustedGetter::evm_account_storages(sender_acc, execution_address, H256::zero())
			.sign(&KeyPair::Sr25519(sender))
			.into();
	let res = perform_operation(cli, trusted_args, &top);

	debug!("received result for balance");
	let val = if let Some(v) = res {
		if let Ok(vd) = H256::decode(&mut v.as_slice()) {
			vd
		} else {
			error!("could not decode value. {:x?}", v);
			H256::zero()
		}
	} else {
		error!("Nothing in state!");
		H256::zero()
	};

	println!("{:?}", val);
}

#[cfg(feature = "evm")]
fn evm_call(
	cli: &Cli,
	trusted_args: &TrustedArgs,
	arg_from: &str,
	execution_address_str: &str,
	function: &str,
) {
	let sender = get_pair_from_str(trusted_args, arg_from);
	let sender_acc: AccountId = sender.public().into();

	println!("senders ss58 is {}", sender.public().to_ss58check());

	let mut sender_evm_acc_slice: [u8; 20] = [0; 20];
	sender_evm_acc_slice
		.copy_from_slice((<[u8; 32]>::from(sender_acc.clone())).get(0..20).unwrap());
	let sender_evm_acc: H160 = sender_evm_acc_slice.into();

	println!("senders evm account is {}", sender_evm_acc);

	let execution_address =
		H160::from_slice(&Vec::from_hex(execution_address_str.to_string()).unwrap());

	let function_hash = Vec::from_hex(function.to_string()).unwrap();

	let (mrenclave, shard) = get_identifiers(trusted_args);
	let nonce = get_layer_two_nonce!(sender, cli, trusted_args);
	let evm_nonce = get_layer_two_evm_nonce!(sender, cli, trusted_args);

	println!("calling smart contract function");
	let function_call = TrustedCall::evm_call(
		sender_acc,
		sender_evm_acc,
		execution_address,
		function_hash,
		U256::from(0),
		10_000_000,    // gas limit
		U256::from(1), // max_fee_per_gas !>= min_gas_price defined in runtime
		None,
		Some(U256::from(evm_nonce)),
		Vec::new(),
	)
	.sign(&KeyPair::Sr25519(sender), nonce, &mrenclave, &shard)
	.into_trusted_operation(trusted_args.direct);
	let _ = perform_operation(cli, trusted_args, &function_call);
}
