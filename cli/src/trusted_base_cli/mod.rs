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

#[cfg(feature = "test")]
use crate::trusted_base_cli::commands::set_balance::SetBalanceCommand;
use crate::{
	trusted_base_cli::commands::{
		add_session_proxy::AddSessionProxyCommand, balance::BalanceCommand,
		get_fingerprint::GetFingerprintCommand, get_header::GetSidechainHeaderCommand,
		get_note_buckets_info::GetNoteBucketsInfoCommand, get_notes::GetNotesCommand,
		get_parentchains_info::GetParentchainsInfoCommand,
		get_session_proxies::GetSessionProxiesCommand, get_shard::GetShardCommand,
		get_shard_info::GetShardInfoCommand, get_shard_vault::GetShardVaultCommand,
		get_total_issuance::GetTotalIssuanceCommand,
		get_undistributed_fees::GetUndistributedFeesCommand, nonce::NonceCommand,
		note_bloat::NoteBloatCommand, spam_extrinsics::SpamExtrinsicsCommand,
		transfer::TransferCommand, unshield_funds::UnshieldFundsCommand, version::VersionCommand,
		waste_time::WasteTimeCommand, watchdog::WatchdogCommand,
	},
	trusted_cli::TrustedCli,
	trusted_command_utils::get_keystore_path,
	Cli, CliResult, CliResultOk, ED25519_KEY_TYPE, SR25519_KEY_TYPE,
};
use log::*;
use sp_core::crypto::Ss58Codec;
use sp_keystore::Keystore;
use substrate_client_keystore::LocalKeystore;

mod commands;

#[derive(Subcommand)]
pub enum TrustedBaseCommand {
	/// generates a new incognito account for the given shard
	NewAccount,

	/// lists all incognito accounts in local keystore in a given shard
	ListAccounts,

	/// send funds from one incognito account to another
	Transfer(TransferCommand),

	/// ROOT call to set some account balance to an arbitrary number
	#[cfg(feature = "test")]
	SetBalance(SetBalanceCommand),

	/// query balance for incognito account in keystore
	Balance(BalanceCommand),

	/// Transfer funds from an incognito account to an parentchain account
	UnshieldFunds(UnshieldFundsCommand),

	/// gets the nonce of a given account, taking the pending trusted calls
	/// in top pool in consideration
	Nonce(NonceCommand),

	/// get fingerprint (AKA MRENCLAVE) for this worker
	GetFingerprint(GetFingerprintCommand),

	/// get shard for this worker
	GetShard(GetShardCommand),

	/// get shard vault for shielding (if defined for this worker)
	GetShardVault(GetShardVaultCommand),

	/// get sidechain header
	GetSidechainHeader(GetSidechainHeaderCommand),

	/// get total issuance of this shard's native token
	GetTotalIssuance(GetTotalIssuanceCommand),

	/// get a noisy amount of collected but undistributed fees
	GetUndistributedFees(GetUndistributedFeesCommand),

	/// get info for all parentchains' sync status
	GetParentchainsInfo(GetParentchainsInfoCommand),

	/// get info for shard like config, status and mode
	GetShardInfo(GetShardInfoCommand),

	/// get info about available note buckets
	GetNoteBucketsInfo(GetNoteBucketsInfoCommand),

	/// get notes for account
	GetNotes(GetNotesCommand),

	/// add a delegate (session proxy)
	AddSessionProxy(AddSessionProxyCommand),

	/// add a delegate (session proxy)
	GetSessionProxies(GetSessionProxiesCommand),

	/// waste time for benchmarking
	WasteTime(WasteTimeCommand),

	/// bloat state with dummy notes for benchmarking
	NoteBloat(NoteBloatCommand),

	/// spam extrinsics to a parentchain
	SpamExtrinsics(SpamExtrinsicsCommand),

	/// run a watchdog service to probe a validateer regularly and profile timings
	Watchdog(WatchdogCommand),

	/// get a version string for the enclave
	Version(VersionCommand),
}

impl TrustedBaseCommand {
	pub fn run(&self, cli: &Cli, trusted_cli: &TrustedCli) -> CliResult {
		match self {
			TrustedBaseCommand::NewAccount => new_account(cli, trusted_cli),
			TrustedBaseCommand::ListAccounts => list_accounts(cli, trusted_cli),
			TrustedBaseCommand::Transfer(cmd) => cmd.run(cli, trusted_cli),
			#[cfg(feature = "test")]
			TrustedBaseCommand::SetBalance(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::Balance(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::UnshieldFunds(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::Nonce(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::GetFingerprint(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::GetParentchainsInfo(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::GetNoteBucketsInfo(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::GetNotes(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::GetShard(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::GetShardInfo(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::GetShardVault(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::GetSidechainHeader(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::GetTotalIssuance(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::GetUndistributedFees(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::AddSessionProxy(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::GetSessionProxies(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::NoteBloat(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::WasteTime(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::SpamExtrinsics(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::Watchdog(cmd) => cmd.run(cli, trusted_cli),
			TrustedBaseCommand::Version(cmd) => cmd.run(cli, trusted_cli),
		}
	}
}

fn new_account(cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
	let store = LocalKeystore::open(get_keystore_path(cli, trusted_args), None).unwrap();
	let key = LocalKeystore::sr25519_generate_new(&store, SR25519_KEY_TYPE, None).unwrap();
	drop(store);
	info!("new account {}", key.to_ss58check());
	let key_str = key.to_ss58check();
	println!("{}", key_str);

	Ok(CliResultOk::PubKeysBase58 { pubkeys_sr25519: Some(vec![key_str]), pubkeys_ed25519: None })
}

fn list_accounts(cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
	let store = LocalKeystore::open(get_keystore_path(cli, trusted_args), None).unwrap();
	info!("sr25519 keys:");
	for pubkey in store.sr25519_public_keys(SR25519_KEY_TYPE).into_iter() {
		println!("{}", pubkey.to_ss58check());
	}
	info!("ed25519 keys:");
	let pubkeys: Vec<String> = store
		.ed25519_public_keys(ED25519_KEY_TYPE)
		.into_iter()
		.map(|pubkey| pubkey.to_ss58check())
		.collect();
	for pubkey in &pubkeys {
		println!("{}", pubkey);
	}
	drop(store);

	Ok(CliResultOk::PubKeysBase58 { pubkeys_sr25519: None, pubkeys_ed25519: Some(pubkeys) })
}
