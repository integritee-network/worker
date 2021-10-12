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
	AccountId, Hash, Index, KeyPair, ShardIdentifier, TrustedCall, TrustedGetter, TrustedOperation,
};
use base58::{FromBase58, ToBase58};
use clap::{AppSettings, Arg, ArgMatches};
use clap_nested::{Command, Commander, MultiCommand};
use codec::{Decode, Encode};
use log::*;
use pallet_rps::WeaponType;
use sp_application_crypto::{ed25519, sr25519};
use sp_core::{crypto::Ss58Codec, sr25519 as sr25519_core, Pair};
use sp_runtime::traits::IdentifyAccount;
use std::path::PathBuf;
use substrate_client_keystore::{KeystoreExt, LocalKeystore};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const KEYSTORE_PATH: &str = "my_trusted_keystore";

pub fn cmd<'a>(
	perform_operation: &'a dyn Fn(&ArgMatches<'_>, &TrustedOperation) -> Option<Vec<u8>>,
) -> MultiCommand<'a, str, str> {
	macro_rules! get_layer_two_nonce {
		($signer_pair:ident, $matches:ident ) => {{
			let top: TrustedOperation =
				TrustedGetter::nonce(sr25519_core::Public::from($signer_pair.public()).into())
					.sign(&KeyPair::Sr25519($signer_pair.clone()))
					.into();
			let res = perform_operation($matches, &top);
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
	Commander::new()
		.options(|app| {
			app.setting(AppSettings::ColoredHelp)
				.arg(
					Arg::with_name("mrenclave")
						.short("m")
						.long("mrenclave")
						.global(true)
						.takes_value(true)
						.value_name("STRING")
						.help("targeted worker MRENCLAVE"),
				)
				.arg(
					Arg::with_name("shard")
						.short("s")
						.long("shard")
						.global(true)
						.takes_value(true)
						.value_name("STRING")
						.help("shard identifier"),
				)
				.arg(
					Arg::with_name("xt-signer")
						.short("a")
						.long("xt-signer")
						.global(true)
						.takes_value(true)
						.value_name("AccountId")
						.default_value("//Alice")
						.help("signer for publicly observable extrinsic"),
				)
				.arg(
					Arg::with_name("direct")
						.short("d")
						.long("direct")
						.global(true)
						.help("insert if direct invocation call is desired"),
				)
				.name("integritee-cli")
				.version(VERSION)
				.author("Integritee AG <hello@integritee.network>")
				.about("trusted calls to worker enclave")
				.after_help("stf subcommands depend on the stf crate this has been built against")
		})
		.add_cmd(
			Command::new("new-account")
				.description("generates a new incognito account for the given integritee shard")
				.runner(|_args: &str, matches: &ArgMatches<'_>| {
					let store = LocalKeystore::open(get_keystore_path(matches), None).unwrap();
					let key: sr25519::AppPair = store.generate().unwrap();
					drop(store);
					println!("{}", key.public().to_ss58check());
					Ok(())
				}),
		)
		.add_cmd(
			Command::new("list-accounts")
				.description("lists all accounts in keystore for the integritee chain")
				.runner(|_args: &str, matches: &ArgMatches<'_>| {
					let store = LocalKeystore::open(get_keystore_path(matches), None).unwrap();
					info!("sr25519 keys:");
					for pubkey in store.public_keys::<sr25519::AppPublic>().unwrap().into_iter() {
						println!("{}", pubkey.to_ss58check());
					}
					info!("ed25519 keys:");
					for pubkey in store.public_keys::<ed25519::AppPublic>().unwrap().into_iter() {
						println!("{}", pubkey.to_ss58check());
					}
					drop(store);
					Ok(())
				}),
		)
		.add_cmd(
			Command::new("transfer")
				.description("send funds from one incognito account to another")
				.options(|app| {
					app.setting(AppSettings::ColoredHelp)
						.arg(
							Arg::with_name("from")
								.takes_value(true)
								.required(true)
								.value_name("SS58")
								.help("sender's AccountId in ss58check format"),
						)
						.arg(
							Arg::with_name("to")
								.takes_value(true)
								.required(true)
								.value_name("SS58")
								.help("recipient's AccountId in ss58check format"),
						)
						.arg(
							Arg::with_name("amount")
								.takes_value(true)
								.required(true)
								.value_name("U128")
								.help("amount to be transferred"),
						)
				})
				.runner(move |_args: &str, matches: &ArgMatches<'_>| {
					let arg_from = matches.value_of("from").unwrap();
					let arg_to = matches.value_of("to").unwrap();
					let amount = matches
						.value_of("amount")
						.unwrap()
						.parse()
						.expect("amount can be converted to u128");
					let from = get_pair_from_str(matches, arg_from);
					let to = get_accountid_from_str(arg_to);
					let direct: bool = matches.is_present("direct");
					info!("from ss58 is {}", from.public().to_ss58check());
					info!("to ss58 is {}", to.to_ss58check());

					println!(
						"send trusted call transfer from {} to {}: {}",
						from.public(),
						to,
						amount
					);
					let (mrenclave, shard) = get_identifiers(matches);
					let nonce = get_layer_two_nonce!(from, matches);
					let top: TrustedOperation =
						TrustedCall::balance_transfer(from.public().into(), to, amount)
							.sign(&KeyPair::Sr25519(from), nonce, &mrenclave, &shard)
							.into_trusted_operation(direct);
					let _ = perform_operation(matches, &top);
					Ok(())
				}),
		)
		.add_cmd(
			Command::new("set-balance")
				.description("ROOT call to set some account balance to an arbitrary number")
				.options(|app| {
					app.arg(
						Arg::with_name("account")
							.takes_value(true)
							.required(true)
							.value_name("SS58")
							.help("sender's AccountId in ss58check format"),
					)
					.arg(
						Arg::with_name("amount")
							.takes_value(true)
							.required(true)
							.value_name("U128")
							.help("amount to be transferred"),
					)
				})
				.runner(move |_args: &str, matches: &ArgMatches<'_>| {
					let arg_who = matches.value_of("account").unwrap();
					let amount = matches
						.value_of("amount")
						.unwrap()
						.parse()
						.expect("amount can be converted to u128");
					let who = get_pair_from_str(matches, arg_who);
					let signer = get_pair_from_str(matches, "//Alice");
					let direct: bool = matches.is_present("direct");
					info!("account ss58 is {}", who.public().to_ss58check());

					println!("send trusted call set-balance({}, {})", who.public(), amount);

					let (mrenclave, shard) = get_identifiers(matches);
					let nonce = get_layer_two_nonce!(signer, matches);
					let top: TrustedOperation = TrustedCall::balance_set_balance(
						signer.public().into(),
						who.public().into(),
						amount,
						amount,
					)
					.sign(&KeyPair::Sr25519(signer), nonce, &mrenclave, &shard)
					.into_trusted_operation(direct);
					let _ = perform_operation(matches, &top);
					Ok(())
				}),
		)
		.add_cmd(
			Command::new("balance")
				.description("query balance for incognito account in keystore")
				.options(|app| {
					app.arg(
						Arg::with_name("accountid")
							.takes_value(true)
							.required(true)
							.value_name("SS58")
							.help("AccountId in ss58check format"),
					)
				})
				.runner(move |_args: &str, matches: &ArgMatches<'_>| {
					let arg_who = matches.value_of("accountid").unwrap();
					debug!("arg_who = {:?}", arg_who);
					let who = get_pair_from_str(matches, arg_who);
					let top: TrustedOperation = TrustedGetter::free_balance(who.public().into())
						.sign(&KeyPair::Sr25519(who))
						.into();
					let res = perform_operation(matches, &top);
					debug!("received result for balance");
					let bal = if let Some(v) = res {
						if let Ok(vd) = crate::Balance::decode(&mut v.as_slice()) {
							vd
						} else {
							info!("could not decode value. maybe hasn't been set? {:x?}", v);
							0
						}
					} else {
						0
					};
					println!("{}", bal);
					Ok(())
				}),
		)
		.add_cmd(
			Command::new("unshield-funds")
				.description("Transfer funds from an incognito account to an on-chain account")
				.options(|app| {
					app.arg(
						Arg::with_name("from")
							.takes_value(true)
							.required(true)
							.value_name("SS58")
							.help("Sender's incognito AccountId in ss58check format"),
					)
					.arg(
						Arg::with_name("to")
							.takes_value(true)
							.required(true)
							.value_name("SS58")
							.help("Recipient's on-chain AccountId in ss58check format"),
					)
					.arg(
						Arg::with_name("amount")
							.takes_value(true)
							.required(true)
							.value_name("U128")
							.help("Amount to be transferred"),
					)
					.arg(
						Arg::with_name("shard")
							.takes_value(true)
							.required(true)
							.value_name("STRING")
							.help("Shard identifier"),
					)
				})
				.runner(move |_args: &str, matches: &ArgMatches<'_>| {
					let arg_from = matches.value_of("from").unwrap();
					let arg_to = matches.value_of("to").unwrap();
					let amount = matches
						.value_of("amount")
						.unwrap()
						.parse()
						.expect("amount can be converted to u128");
					let from = get_pair_from_str(matches, arg_from);
					let to = get_accountid_from_str(arg_to);
					let direct: bool = matches.is_present("direct");
					println!("from ss58 is {}", from.public().to_ss58check());
					println!("to   ss58 is {}", to.to_ss58check());

					println!(
						"send trusted call unshield_funds from {} to {}: {}",
						from.public(),
						to,
						amount
					);

					let (mrenclave, shard) = get_identifiers(matches);
					let nonce = get_layer_two_nonce!(from, matches);
					let top: TrustedOperation =
						TrustedCall::balance_unshield(from.public().into(), to, amount, shard)
							.sign(&KeyPair::Sr25519(from), nonce, &mrenclave, &shard)
							.into_trusted_operation(direct);
					let _ = perform_operation(matches, &top);
					Ok(())
				}),
		)
		.add_cmd(
			Command::new("new-game")
				.description("create new RPS game")
				.options(|app| {
					app.setting(AppSettings::ColoredHelp)
						.arg(
							Arg::with_name("creator")
								.takes_value(true)
								.required(true)
								.value_name("SS58")
								.help("sender's AccountId in ss58check format"),
						)
						.arg(
							Arg::with_name("opponent")
								.takes_value(true)
								.required(true)
								.value_name("SS58")
								.help("opponent's AccountId in ss58check format"),
						)
				})
				.runner(move |_args: &str, matches: &ArgMatches<'_>| {
					let arg_creator = matches.value_of("creator").unwrap();
					let arg_opponent = matches.value_of("opponent").unwrap();
					let creator = get_pair_from_str(matches, arg_creator);
					let opponent = get_accountid_from_str(arg_opponent);
					let direct: bool = matches.is_present("direct");
					info!("creator ss58 is {}", creator.public().to_ss58check());
					info!("opponent ss58 is {}", opponent.to_ss58check());

					println!(
						"send trusted call rps_new_game from {} with opponent {}",
						creator.public(),
						opponent
					);
					let (mrenclave, shard) = get_identifiers(matches);
					let nonce = get_layer_two_nonce!(creator, matches);
					let top: TrustedOperation =
						TrustedCall::rps_new_game(creator.public().into(), opponent)
							.sign(&KeyPair::Sr25519(creator), nonce, &mrenclave, &shard)
							.into_trusted_operation(direct);
					let _ = perform_operation(matches, &top);
					Ok(())
				}),
		)
		.add_cmd(
			Command::new("choose")
				.description("choose RPS")
				.options(|app| {
					app.setting(AppSettings::ColoredHelp)
						.arg(
							Arg::with_name("player")
								.takes_value(true)
								.required(true)
								.value_name("SS58")
								.help("player's AccountId in ss58check format"),
						)
						.arg(
							Arg::with_name("weapon")
								.takes_value(true)
								.required(true)
								.value_name("RPS")
								.help("weapon choice. One of 'Rock', 'Paper' or 'Scissors'"),
						)
				})
				.runner(move |_args: &str, matches: &ArgMatches<'_>| {
					let arg_player = matches.value_of("player").unwrap();
					let weapon: WeaponType = match matches.value_of("weapon").unwrap() {
						r"Rock" => WeaponType::Rock,
						r"Paper" => WeaponType::Paper,
						r"Scissors" => WeaponType::Scissors,
						_ => panic!("unknown weapon type"),
					};
					let player = get_pair_from_str(matches, arg_player);
					let direct: bool = matches.is_present("direct");
					info!("player ss58 is {}", player.public().to_ss58check());
					info!("weapon choice is {:?}", weapon);

					println!(
						"send trusted call rps_choose from {} with weapon {:?}",
						player.public(),
						weapon
					);
					let (mrenclave, shard) = get_identifiers(matches);
					let nonce = get_layer_two_nonce!(player, matches);
					let top: TrustedOperation =
						TrustedCall::rps_choose(player.public().into(), weapon)
							.sign(&KeyPair::Sr25519(player), nonce, &mrenclave, &shard)
							.into_trusted_operation(direct);
					let _ = perform_operation(matches, &top);
					Ok(())
				}),
		)
		.add_cmd(
			Command::new("reveal")
				.description("reveal RPS")
				.options(|app| {
					app.setting(AppSettings::ColoredHelp)
						.arg(
							Arg::with_name("player")
								.takes_value(true)
								.required(true)
								.value_name("SS58")
								.help("player's AccountId in ss58check format"),
						)
						.arg(
							Arg::with_name("weapon")
								.takes_value(true)
								.required(true)
								.value_name("RPS")
								.help("weapon choice. One of 'Rock', 'Paper' or 'Scissors'"),
						)
				})
				.runner(move |_args: &str, matches: &ArgMatches<'_>| {
					let arg_player = matches.value_of("player").unwrap();
					let weapon: WeaponType = match matches.value_of("weapon").unwrap() {
						r"Rock" => WeaponType::Rock,
						r"Paper" => WeaponType::Paper,
						r"Scissors" => WeaponType::Scissors,
						_ => panic!("unknown weapon type"),
					};
					let player = get_pair_from_str(matches, arg_player);
					let direct: bool = matches.is_present("direct");
					info!("player ss58 is {}", player.public().to_ss58check());
					info!("weapon choice is {:?}", weapon);

					println!(
						"send trusted call rps_reveal from {} with weapon {:?}",
						player.public(),
						weapon
					);
					let (mrenclave, shard) = get_identifiers(matches);
					let nonce = get_layer_two_nonce!(player, matches);
					let top: TrustedOperation =
						TrustedCall::rps_reveal(player.public().into(), weapon)
							.sign(&KeyPair::Sr25519(player), nonce, &mrenclave, &shard)
							.into_trusted_operation(direct);
					let _ = perform_operation(matches, &top);
					Ok(())
				}),
		)
		.add_cmd(
			Command::new("get-game")
				.description("query game state for account in keystore")
				.options(|app| {
					app.arg(
						Arg::with_name("accountid")
							.takes_value(true)
							.required(true)
							.value_name("SS58")
							.help("AccountId in ss58check format"),
					)
				})
				.runner(move |_args: &str, matches: &ArgMatches<'_>| {
					let arg_who = matches.value_of("accountid").unwrap();
					debug!("arg_who = {:?}", arg_who);
					let player = get_pair_from_str(matches, arg_who);
					let top: TrustedOperation = TrustedGetter::game(player.public().into())
						.sign(&KeyPair::Sr25519(player))
						.into();
					let res = perform_operation(matches, &top);
					debug!("received result for game");
					if let Some(v) = res {
						if let Ok(game) =
							pallet_rps::Game::<Hash, AccountId>::decode(&mut v.as_slice())
						{
							println!("game state for {:?} ", game.id);
							println!(
								"player {}: {:?}",
								game.players[0].to_ss58check(),
								game.states[0]
							);
							println!(
								"player {}: {:?}",
								game.players[1].to_ss58check(),
								game.states[1]
							);
						} else {
							println!("could not decode game. maybe hasn't been set? {:x?}", v);
						}
					} else {
						println!("could not fetch game");
					};

					Ok(())
				}),
		)
		.into_cmd("trusted")
}

fn get_keystore_path(matches: &ArgMatches<'_>) -> PathBuf {
	let (_mrenclave, shard) = get_identifiers(matches);
	PathBuf::from(&format!("{}/{}", KEYSTORE_PATH, shard.encode().to_base58()))
}

pub fn get_identifiers(matches: &ArgMatches<'_>) -> ([u8; 32], ShardIdentifier) {
	let mut mrenclave = [0u8; 32];
	if !matches.is_present("mrenclave") {
		panic!("--mrenclave must be provided");
	};
	mrenclave.copy_from_slice(
		&matches
			.value_of("mrenclave")
			.unwrap()
			.from_base58()
			.expect("mrenclave has to be base58 encoded"),
	);
	let shard = match matches.value_of("shard") {
		Some(val) =>
			ShardIdentifier::from_slice(&val.from_base58().expect("shard has to be base58 encoded")),
		None => ShardIdentifier::from_slice(&mrenclave),
	};
	(mrenclave, shard)
}

// TODO this function is redundant with client::main
fn get_accountid_from_str(account: &str) -> AccountId {
	match &account[..2] {
		"//" => sr25519::Pair::from_string(account, None)
			.unwrap()
			.public()
			.into_account()
			.into(),
		_ => sr25519::Public::from_ss58check(account).unwrap().into_account().into(),
	}
}

// TODO this function is ALMOST redundant with client::main
// get a pair either form keyring (well known keys) or from the store
fn get_pair_from_str(matches: &ArgMatches<'_>, account: &str) -> sr25519_core::Pair {
	info!("getting pair for {}", account);
	match &account[..2] {
		"//" => sr25519_core::Pair::from_string(account, None).unwrap(),
		_ => {
			info!("fetching from keystore at {}", &KEYSTORE_PATH);
			// open store without password protection
			let store =
				LocalKeystore::open(get_keystore_path(matches), None).expect("store should exist");
			info!("store opened");
			let _pair = store
				.key_pair::<sr25519::AppPair>(
					&sr25519::Public::from_ss58check(account).unwrap().into(),
				)
				.unwrap()
				.unwrap();
			info!("key pair fetched");
			drop(store);
			_pair.into()
		},
	}
}
