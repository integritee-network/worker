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
	trusted_command_utils::{get_accountid_from_str, get_identifiers, get_pair_from_str},
	trusted_commands::TrustedArgs,
	trusted_operation::perform_trusted_operation,
	Cli,
};
use ita_stf::{AccountId, Hash, KeyPair, TrustedCall, TrustedGetter, TrustedOperation};
use log::*;
use pallet_rps::WeaponType;
use sp_core::Pair;

/// Create a new RPS game.
pub(crate) fn new_rps_game(
	cli: &Cli,
	trusted_args: &TrustedArgs,
	player_creator: &str,
	player_opponent: &str,
) {
	let creator = get_pair_from_str(trusted_args, player_creator);
	let opponent = get_accountid_from_str(player_opponent);
	let direct: bool = trusted_args.direct;

	info!("creator ss58 is {}", creator.public().to_ss58check());
	info!("opponent ss58 is {}", opponent.to_ss58check());

	println!("send trusted call rps_new_game from {} with opponent {}", creator.public(), opponent);

	let (mrenclave, shard) = get_identifiers(trusted_args);
	let nonce = get_layer_two_nonce!(player_creator, cli, trusted_args);

	let top: TrustedOperation = TrustedCall::rps_new_game(creator.public().into(), opponent)
		.sign(&KeyPair::Sr25519(creator), nonce, &mrenclave, &shard)
		.into_trusted_operation(direct);

	let _ = perform_trusted_operation(cli, trusted_args, &top);
}

/// Choose RPS weapon for a player.
pub(crate) fn rps_choose(
	cli: &Cli,
	trusted_args: &TrustedArgs,
	arg_player: &str,
	arg_weapon: &str,
) {
	let player = get_pair_from_str(trusted_args, arg_player);
	let weapon = string_to_weapon(arg_weapon);
	let direct: bool = trusted_args.direct;

	info!("player ss58 is {}", player.public().to_ss58check());
	info!("weapon choice is {:?}", weapon);

	println!("send trusted call rps_choose from {} with weapon {:?}", player.public(), weapon);
	let (mrenclave, shard) = get_identifiers(trusted_args);
	let nonce = get_layer_two_nonce!(player, cli, trusted_args);
	let top: TrustedOperation = TrustedCall::rps_choose(player.public().into(), weapon)
		.sign(&KeyPair::Sr25519(player), nonce, &mrenclave, &shard)
		.into_trusted_operation(direct);

	let _ = perform_trusted_operation(cli, trusted_args, &top);
}

/// Reveal a player's weapon.
pub(crate) fn rps_reveal(
	cli: &Cli,
	trusted_args: &TrustedArgs,
	arg_player: &str,
	arg_weapon: &str,
) {
	let player = get_pair_from_str(trusted_args, arg_player);
	let weapon = string_to_weapon(arg_weapon);
	let direct: bool = trusted_args.direct;

	info!("player ss58 is {}", player.public().to_ss58check());
	info!("weapon choice is {:?}", weapon);

	println!("send trusted call rps_reveal from {} with weapon {:?}", player.public(), weapon);

	let (mrenclave, shard) = get_identifiers(trusted_args);
	let nonce = get_layer_two_nonce!(player, cli, trusted_args);
	let top: TrustedOperation = TrustedCall::rps_reveal(player.public().into(), weapon)
		.sign(&KeyPair::Sr25519(player), nonce, &mrenclave, &shard)
		.into_trusted_operation(direct);
	let _ = perform_trusted_operation(cli, trusted_args, &top);
}

/// Query game state for a specific player.
pub(crate) fn rps_get_game(cli: &Cli, trusted_args: &TrustedArgs, arg_player: &str) {
	let player = get_pair_from_str(trusted_args, arg_player);
	let top: TrustedOperation = TrustedGetter::game(player.public().into())
		.sign(&KeyPair::Sr25519(player))
		.into();

	let getter_result = perform_trusted_operation(cli, trusted_args, &top);

	debug!("received result for game");
	if let Some(v) = getter_result {
		if let Ok(game) = pallet_rps::Game::<Hash, AccountId>::decode(&mut v.as_slice()) {
			println!("game state for {:?} ", game.id);
			println!("player {}: {:?}", game.players[0].to_ss58check(), game.states[0]);
			println!("player {}: {:?}", game.players[1].to_ss58check(), game.states[1]);
		} else {
			println!("could not decode game. maybe hasn't been set? {:x?}", v);
		}
	} else {
		println!("could not fetch game");
	};
}

/// Convert a string to a weapon. Panics if conversion fails.
fn string_to_weapon(weapon_str: &str) -> WeaponType {
	match weapon_str {
		r"Rock" => WeaponType::Rock,
		r"Paper" => WeaponType::Paper,
		r"Scissors" => WeaponType::Scissors,
		_ => panic!("unknown weapon type"),
	}
}
