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

use crate::trusted_commands::TrustedArgs;
use base58::{FromBase58, ToBase58};
use codec::Encode;
use ita_stf::{AccountId, ShardIdentifier};
use log::*;
use sp_application_crypto::sr25519;
use sp_core::{crypto::Ss58Codec, sr25519 as sr25519_core, Pair};
use sp_runtime::traits::IdentifyAccount;
use std::path::PathBuf;
use substrate_client_keystore::LocalKeystore;

const TRUSTED_KEYSTORE_PATH: &str = "my_trusted_keystore";

pub(crate) fn get_keystore_path(trusted_args: &TrustedArgs) -> PathBuf {
	let (_mrenclave, shard) = get_identifiers(trusted_args);
	PathBuf::from(&format!("{}/{}", TRUSTED_KEYSTORE_PATH, shard.encode().to_base58()))
}

pub(crate) fn get_identifiers(trusted_args: &TrustedArgs) -> ([u8; 32], ShardIdentifier) {
	let mut mrenclave = [0u8; 32];
	mrenclave.copy_from_slice(
		&trusted_args
			.mrenclave
			.from_base58()
			.expect("mrenclave has to be base58 encoded"),
	);
	let shard = match &trusted_args.shard {
		Some(val) =>
			ShardIdentifier::from_slice(&val.from_base58().expect("shard has to be base58 encoded")),
		None => ShardIdentifier::from_slice(&mrenclave),
	};
	(mrenclave, shard)
}

// TODO this function is redundant with client::main
pub(crate) fn get_accountid_from_str(account: &str) -> AccountId {
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
pub(crate) fn get_pair_from_str(trusted_args: &TrustedArgs, account: &str) -> sr25519_core::Pair {
	info!("getting pair for {}", account);
	match &account[..2] {
		"//" => sr25519_core::Pair::from_string(account, None).unwrap(),
		_ => {
			info!("fetching from keystore at {}", &TRUSTED_KEYSTORE_PATH);
			// open store without password protection
			let store = LocalKeystore::open(get_keystore_path(trusted_args), None)
				.expect("store should exist");
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
