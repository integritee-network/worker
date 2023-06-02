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
	trusted_base_cli::commands::{
		balance::BalanceCommand, nonce::NonceCommand, set_balance::SetBalanceCommand,
		transfer::TransferCommand, unshield_funds::UnshieldFundsCommand,
	},
	trusted_cli::TrustedCli,
	trusted_command_utils::get_keystore_path,
	Cli, CliResult, CliResultOk,
};
use log::*;
use sp_core::crypto::{key_types::ACCOUNT, Ss58Codec};
use sp_keystore::Keystore;
use substrate_client_keystore::LocalKeystore;

mod commands;

#[derive(Subcommand)]
pub enum TrustedBaseCommand {
	/// generates a new incognito account for the given shard
	NewAccount,

	/// lists all incognito accounts in a given shard
	ListAccounts,

	/// send funds from one incognito account to another
	Transfer(TransferCommand),

	/// ROOT call to set some account balance to an arbitrary number
	SetBalance(SetBalanceCommand),

	/// query balance for incognito account in keystore
	Balance(BalanceCommand),

	/// Transfer funds from an incognito account to an parentchain account
	UnshieldFunds(UnshieldFundsCommand),

	/// gets the nonce of a given account, taking the pending trusted calls
	/// in top pool in consideration
	Nonce(NonceCommand),
}

impl TrustedBaseCommand {
	pub fn run(&self, cli: &Cli, trusted_cli: &TrustedCli) -> CliResult {
		match self {
			TrustedBaseCommand::NewAccount => new_account(trusted_cli),
			TrustedBaseCommand::ListAccounts => list_accounts(trusted_cli),
			TrustedBaseCommand::Transfer(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::SetBalance(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::Balance(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::UnshieldFunds(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::Nonce(cmd) => cmd.run(cli, trusted_cli),
		}
	}
}

fn new_account(trusted_args: &TrustedCli) -> CliResult {
	let store = LocalKeystore::open(get_keystore_path(trusted_args), None).unwrap();
	let key = LocalKeystore::sr25519_generate_new(&store, ACCOUNT, None).unwrap();
	drop(store);
	info!("new account {}", key.to_ss58check());
	let key_str = key.to_ss58check();
	println!("{}", key_str);

	Ok(CliResultOk::PubKeysBase58 { pubkeys_sr25519: Some(vec![key_str]), pubkeys_ed25519: None })
}

fn list_accounts(trusted_args: &TrustedCli) -> CliResult {
	let store = LocalKeystore::open(get_keystore_path(trusted_args), None).unwrap();
	info!("sr25519 keys:");
	for pubkey in store.sr25519_public_keys(ACCOUNT).into_iter() {
		println!("{}", pubkey.to_ss58check());
	}
	info!("ed25519 keys:");
	let pubkeys: Vec<String> = store
		.ed25519_public_keys(ACCOUNT)
		.into_iter()
		.map(|pubkey| pubkey.to_ss58check())
		.collect();
	for pubkey in &pubkeys {
		println!("{}", pubkey);
	}
	drop(store);

	Ok(CliResultOk::PubKeysBase58 { pubkeys_sr25519: None, pubkeys_ed25519: Some(pubkeys) })
}
