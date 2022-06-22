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
	trusted_command_utils::{
		get_accountid_from_str, get_identifiers, get_keystore_path, get_pair_from_str,
	},
	trusted_operation::perform_trusted_operation,
	Cli,
};
use codec::Decode;
use ita_stf::{
	Coordinates, Index, KeyPair, SgxGameBoardStruct, SgxGameTurn, Side, TrustedCall, TrustedGetter,
	TrustedOperation,
};
use log::*;
use my_node_runtime::Balance;
use sp_application_crypto::{ed25519, sr25519};
use sp_core::{crypto::Ss58Codec, sr25519 as sr25519_core, Pair};
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

	/// Play a turn of a board game
	DropBomb {
		/// Player's incognito AccountId in ss58check format
		player: String,
		// Column
		col: u8,
		// Row
		row: u8,
	},

	DropStone {
		player: String,
		side: SideCommand,
		n: u8,
	},

	/// Query board state for account in keystore
	GetBoard {
		/// Player's incognito AccountId in ss58check format
		player: String,
	},
}

pub struct SideCommand(Side);
use std::str::FromStr;

impl FromStr for SideCommand {
	type Err = &'static str;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.eq("north") {
			return Ok(SideCommand(Side::North))
		}
		if s.eq("east") {
			return Ok(SideCommand(Side::East))
		}
		if s.eq("south") {
			return Ok(SideCommand(Side::South))
		}
		if s.eq("west") {
			return Ok(SideCommand(Side::West))
		}
		Err("Invalid side")
	}
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
		TrustedCommands::DropBomb { player, col, row } => play_turn(
			cli,
			trusted_args,
			player,
			SgxGameTurn::DropBomb(Coordinates { col: *col, row: *row }),
		),
		TrustedCommands::DropStone { player, side, n } =>
			play_turn(cli, trusted_args, player, SgxGameTurn::DropStone(((*side).0.clone(), *n))),
		TrustedCommands::GetBoard { player } => get_board(cli, trusted_args, player),
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

fn play_turn(cli: &Cli, trusted_args: &TrustedArgs, arg_player: &str, turn: SgxGameTurn) {
	let player = get_pair_from_str(trusted_args, arg_player);
	println!("player ss58 is {}", player.public().to_ss58check());

	println!("send trusted call play-turn from {} with turn {:?}", player.public(), turn);
	let (mrenclave, shard) = get_identifiers(trusted_args);
	let nonce = get_layer_two_nonce!(player, cli, trusted_args);

	let top: TrustedOperation = TrustedCall::board_play_turn(player.public().into(), turn)
		.sign(&KeyPair::Sr25519(player), nonce, &mrenclave, &shard)
		.into_trusted_operation(trusted_args.direct);
	let _ = perform_operation(cli, trusted_args, &top);
}

fn get_board(cli: &Cli, trusted_args: &TrustedArgs, arg_player: &str) {
	let player = get_pair_from_str(trusted_args, arg_player);
	let top: TrustedOperation = TrustedGetter::board(player.public().into())
		.sign(&KeyPair::Sr25519(player))
		.into();
	let res = perform_operation(cli, trusted_args, &top);
	debug!("received result for board");
	if let Some(v) = res {
		if let Ok(board) = SgxGameBoardStruct::decode(&mut v.as_slice()) {
			println!("Board: {:?}", board.state);
		} else {
			println!("could not decode board. maybe hasn't been set? {:x?}", v);
		}
	} else {
		println!("could not fetch board");
	};
}
