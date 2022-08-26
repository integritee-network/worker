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
		balance::BalanceCommand, set_balance::SetBalanceCommand, transfer::TransferCommand,
		unshield_funds::UnshieldFundsCommand,
	},
	trusted_command_utils::get_keystore_path,
	trusted_commands::TrustedArgs,
	Cli,
};
use log::*;
use sp_application_crypto::{ed25519, sr25519};
use sp_core::{crypto::Ss58Codec, Pair};
use substrate_client_keystore::{KeystoreExt, LocalKeystore};

mod commands;

#[derive(Subcommand)]
pub enum TrustedBaseCli {
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
}

impl TrustedBaseCli {
	pub fn run(&self, cli: &Cli, trusted_args: &TrustedArgs) {
		match self {
			TrustedBaseCli::NewAccount => new_account(trusted_args),
			TrustedBaseCli::ListAccounts => list_accounts(trusted_args),
			TrustedBaseCli::Transfer(cmd) => cmd.run(cli, trusted_args),
			TrustedBaseCli::SetBalance(cmd) => cmd.run(cli, trusted_args),
			TrustedBaseCli::Balance(cmd) => cmd.run(cli, trusted_args),
			TrustedBaseCli::UnshieldFunds(cmd) => cmd.run(cli, trusted_args),
		}
	}
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
