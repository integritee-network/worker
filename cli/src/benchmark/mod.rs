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
	get_basic_signing_info_from_args,
	trusted_cli::TrustedCli,
	trusted_command_utils::{get_keystore_path, get_pair_from_str, get_trusted_account_info},
	trusted_operation::{await_status, await_subscription_response, get_json_request, get_state},
	Cli, CliResult, CliResultOk, SR25519_KEY_TYPE,
};
use codec::Decode;
use hdrhistogram::Histogram;
use ita_stf::{
	Getter, Index, TrustedCall, TrustedCallSigned, TrustedGetter, STF_TX_FEE_UNIT_DIVIDER,
};
use itc_rpc_client::direct_client::{DirectApi, DirectClient};
use itp_stf_primitives::{
	traits::TrustedCallSigning,
	types::{KeyPair, TrustedOperation},
};
use itp_types::{
	AccountInfo, Balance, ShardIdentifier, TrustedOperationStatus,
	TrustedOperationStatus::InSidechainBlock,
};
use log::*;
use rand::Rng;
use rayon::prelude::*;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sp_application_crypto::sr25519;
use sp_core::{sr25519 as sr25519_core, Pair};
use sp_keystore::Keystore;
use std::{
	boxed::Box,
	string::ToString,
	sync::mpsc::{channel, Receiver, Sender},
	thread, time,
	time::Instant,
	vec::Vec,
};
use substrate_client_keystore::LocalKeystore;

// Needs to be above the existential deposit minimum, otherwise an account will not
// be created and the state is not increased.
const EXISTENTIAL_DEPOSIT: Balance = 1000;

#[derive(Parser)]
pub struct BenchmarkCommand {
	/// The number of clients (=threads) to be used in the benchmark
	#[clap(default_value_t = 10)]
	number_clients: u32,

	/// The number of iterations to execute for each client
	#[clap(default_value_t = 30)]
	number_iterations: u128,

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

	/// session proxy who can sign on behalf of the account
	#[clap(long)]
	session_proxy: Option<String>,
}

struct BenchmarkClient {
	account: sr25519_core::Pair,
	current_balance: u128,
	client_api: DirectClient,
	sender: Sender<String>,
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
		client_api.watch(initial_request, sender.clone());
		BenchmarkClient { account, current_balance: initial_balance, client_api, sender, receiver }
	}
}

/// Stores timing information about a specific transaction
struct BenchmarkTransaction {
	started: Instant,
	submitted: Instant,
	confirmed: Option<Instant>,
}

impl BenchmarkCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let random_wait_before_transaction_ms: (u32, u32) = (
			self.random_wait_before_transaction_min_ms,
			self.random_wait_before_transaction_max_ms,
		);
		let store = LocalKeystore::open(get_keystore_path(cli, trusted_args), None).unwrap();

		let (sender, signer, mrenclave, shard) = get_basic_signing_info_from_args!(
			self.funding_account,
			self.session_proxy,
			cli,
			trusted_args
		);

		// Get shielding pubkey.
		let worker_api_direct = get_worker_api_direct(cli);
		let shielding_pubkey: Rsa3072PubKey = match worker_api_direct.get_rsa_pubkey() {
			Ok(key) => key,
			Err(err_msg) => panic!("{}", err_msg.to_string()),
		};

		let nonce_start = get_trusted_account_info(cli, trusted_args, &sender, &signer)
			.map(|info| info.nonce)
			.unwrap_or_default();

		println!("Nonce for account {}: {}", self.funding_account, nonce_start);

		let mut accounts = Vec::new();
		let initial_balance = (self.number_iterations + 1)
			* (1_000_000_000_000 / STF_TX_FEE_UNIT_DIVIDER + EXISTENTIAL_DEPOSIT);
		// Setup new accounts and initialize them with money from funding_account.
		for i in 0..self.number_clients {
			let nonce = i + nonce_start;
			println!("Initializing account {} with initial amount {:?}", i, initial_balance);

			// Create new account to use.
			let a = LocalKeystore::sr25519_generate_new(&store, SR25519_KEY_TYPE, None).unwrap();
			let account = get_pair_from_str(cli, trusted_args, a.to_string().as_str());

			// Transfer amount from funding_account to new account.
			let top: TrustedOperation<TrustedCallSigned, Getter> = TrustedCall::balance_transfer(
				sender.clone(),
				account.public().into(),
				initial_balance,
			)
			.sign(&KeyPair::Sr25519(Box::new(signer.clone())), nonce, &mrenclave, &shard)
			.into_trusted_operation(true);

			// For the last account we wait for confirmation in order to ensure all accounts were setup correctly
			let wait_for_confirmation = i == self.number_clients - 1;
			let account_funding_request = get_json_request(shard, &top, shielding_pubkey);

			let client =
				BenchmarkClient::new(account, initial_balance, account_funding_request, cli);
			let _result = wait_for_top_confirmation(wait_for_confirmation, &client);
			accounts.push(client);
		}

		rayon::ThreadPoolBuilder::new()
			.num_threads(self.number_clients as usize)
			.build_global()
			.unwrap();

		let overall_start = Instant::now();

		// Run actual benchmark logic, in parallel, for each account initialized above.
		let outputs: Vec<Vec<BenchmarkTransaction>> = accounts
			.into_par_iter()
			.map(move |mut client| {
				let mut output: Vec<BenchmarkTransaction> = Vec::new();

				for i in 0..self.number_iterations {
					println!("Iteration: {}", i);

					if random_wait_before_transaction_ms.1 > 0 {
						random_wait(random_wait_before_transaction_ms);
					}

					// Create new account.
					let account_keys = LocalKeystore::sr25519_generate_new(&store, SR25519_KEY_TYPE, None).unwrap();

					let new_account =
						get_pair_from_str(cli, trusted_args, account_keys.to_string().as_str());


					println!("  Transfer amount: {}", EXISTENTIAL_DEPOSIT);
					println!("  From: {:?}", client.account.public());
					println!("  To:   {:?}", new_account.public());

					// Get nonce of account.
					let nonce = get_nonce(client.account.clone(), shard, &client.client_api);

					// Transfer money from client account to new account.
					let top: TrustedOperation<TrustedCallSigned, Getter> = TrustedCall::balance_transfer(
						client.account.public().into(),
						new_account.public().into(),
						EXISTENTIAL_DEPOSIT,
					)
					.sign(&KeyPair::Sr25519(Box::new(client.account.clone())), nonce, &mrenclave, &shard)
					.into_trusted_operation(trusted_args.direct);

					let last_iteration = i == self.number_iterations - 1;
					let jsonrpc_call = get_json_request(shard, &top, shielding_pubkey);

					client.client_api.watch(jsonrpc_call, client.sender.clone());
					let result = wait_for_top_confirmation(
						self.wait_for_confirmation || last_iteration,
						&client,
					);

					client.current_balance -= EXISTENTIAL_DEPOSIT;

					let balance = get_balance(client.account.clone(), shard, &client.client_api);
					println!("Balance: {}", balance.unwrap_or_default());
					assert_eq!(client.current_balance, balance.unwrap_or_default());

					output.push(result);

					// FIXME: We probably should re-fund the account in this case.
					if client.current_balance <= 1_000_000_000_000 / STF_TX_FEE_UNIT_DIVIDER + EXISTENTIAL_DEPOSIT {
						error!("Account {:?} does not have enough balance anymore. Finishing benchmark early", client.account.public());
						break;
					}
				}

				client.client_api.close().unwrap();

				output
			})
			.collect();

		println!(
			"Finished benchmark with {} clients and {} transactions in {} ms",
			self.number_clients,
			self.number_iterations,
			overall_start.elapsed().as_millis()
		);

		print_benchmark_statistic(outputs, self.wait_for_confirmation);

		Ok(CliResultOk::None)
	}
}

fn get_balance(
	account: sr25519::Pair,
	shard: ShardIdentifier,
	direct_client: &DirectClient,
) -> Option<u128> {
	let getter = Getter::trusted(
		TrustedGetter::account_info(account.public().into())
			.sign(&KeyPair::Sr25519(Box::new(account.clone()))),
	);

	let getter_start_timer = Instant::now();
	let getter_result = get_state(direct_client, shard, &getter).unwrap_or_default();
	let getter_execution_time = getter_start_timer.elapsed().as_millis();

	let balance = decode_balance(getter_result);
	info!("Balance getter execution took {} ms", getter_execution_time,);
	debug!("Retrieved {:?} Balance for {:?}", balance.unwrap_or_default(), account.public());
	balance
}

fn get_nonce(
	account: sr25519::Pair,
	shard: ShardIdentifier,
	direct_client: &DirectClient,
) -> Index {
	let getter = Getter::trusted(
		TrustedGetter::account_info(account.public().into())
			.sign(&KeyPair::Sr25519(Box::new(account.clone()))),
	);

	let getter_start_timer = Instant::now();
	let info = get_state::<AccountInfo>(direct_client, shard, &getter);
	let nonce = info.map(|i| i.nonce).ok().unwrap_or_default();
	let getter_execution_time = getter_start_timer.elapsed().as_millis();
	info!("Nonce getter execution took {} ms", getter_execution_time,);
	debug!("Retrieved {:?} nonce for {:?}", nonce, account.public());
	nonce
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

	// the first response of `submitAndWatch` is just the plain top hash
	let submitted = match await_subscription_response(&client.receiver) {
		Ok(hash) => Some((hash, Instant::now())),
		Err(e) => {
			error!("recv error: {e:?}");
			None
		},
	};

	let confirmed = if wait_for_sidechain_block {
		// We wait for the transaction hash that actually matches the submitted hash
		loop {
			let transaction_information = await_status(&client.receiver, is_sidechain_block).ok();
			if let Some((hash, _status)) = transaction_information {
				if hash == submitted.unwrap().0 {
					break Some((hash, Instant::now()))
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

fn is_sidechain_block(s: TrustedOperationStatus) -> bool {
	matches!(s, InSidechainBlock(_))
}

fn decode_balance(maybe_encoded_balance: Option<Vec<u8>>) -> Option<Balance> {
	maybe_encoded_balance.and_then(|encoded_balance| {
		if let Ok(vd) = AccountInfo::decode(&mut encoded_balance.as_slice()) {
			Some(vd.data.free)
		} else {
			warn!("Could not decode balance. maybe hasn't been set? {:x?}", encoded_balance);
			None
		}
	})
}
