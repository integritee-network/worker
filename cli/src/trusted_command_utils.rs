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
	command_utils::mrenclave_from_base58, trusted_cli::TrustedCli,
	trusted_operation::perform_trusted_operation, Cli,
};
use base58::{FromBase58, ToBase58};
use codec::Encode;
use ita_stf::{Getter, TrustedCallSigned, TrustedGetter};
use itp_stf_primitives::types::{AccountId, KeyPair, ShardIdentifier, TrustedOperation};
use itp_types::AccountInfo;
use log::*;
use sp_application_crypto::sr25519;
use sp_core::{crypto::Ss58Codec, sr25519 as sr25519_core, Pair};
use sp_runtime::traits::IdentifyAccount;
use std::{boxed::Box, path::PathBuf};
use substrate_client_keystore::LocalKeystore;

const TRUSTED_KEYSTORE_PATH: &str = "my_trusted_keystore";

#[macro_export]
macro_rules! get_sender_and_signer_from_args {
	($sender:expr, $maybe_session_proxy:expr, $trusted_args:ident ) => {{
		use crate::trusted_command_utils::{get_account_id_from_str, get_pair_from_str};
		use itp_stf_primitives::types::AccountId;
		use log::debug;
		use sp_application_crypto::{sr25519, Pair};
		use sp_core::crypto::Ss58Codec;

		let sender: AccountId = get_account_id_from_str($sender.as_str());
		let signer = $maybe_session_proxy
			.as_ref()
			.map(|proxy| get_pair_from_str($trusted_args, proxy.as_str()))
			.unwrap_or_else(|| get_pair_from_str($trusted_args, $sender.as_str()));
		debug!(
			"get_sender_and_signer_from_args: sender = {:?}, signer: {:?}",
			sender.to_ss58check(),
			signer.public().to_ss58check()
		);
		(sender, signer)
	}};
}

pub(crate) fn get_trusted_account_info(
	cli: &Cli,
	trusted_args: &TrustedCli,
	subject: &AccountId,
	signer: &sr25519_core::Pair,
) -> Option<AccountInfo> {
	debug!(
		"get_trusted_account_info: subject = {:?}, signer: {:?}",
		subject.to_ss58check(),
		signer.public().to_ss58check()
	);
	let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::trusted(
		TrustedGetter::account_info(subject.clone())
			.sign(&KeyPair::Sr25519(Box::new(signer.clone()))),
	));
	let maybe_info = perform_trusted_operation::<AccountInfo>(cli, trusted_args, &top).ok();
	debug!("get_trusted_account_info: result: {:?}", maybe_info);
	maybe_info
}

pub(crate) fn get_keystore_path(trusted_args: &TrustedCli) -> PathBuf {
	let (_mrenclave, shard) = get_identifiers(trusted_args);
	PathBuf::from(&format!("{}/{}", TRUSTED_KEYSTORE_PATH, shard.encode().to_base58()))
}

pub(crate) fn get_identifiers(trusted_args: &TrustedCli) -> ([u8; 32], ShardIdentifier) {
	let mrenclave = mrenclave_from_base58(
		trusted_args
			.mrenclave
			.as_ref()
			.expect("argument '--mrenclave' must be provided for this command"),
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
pub(crate) fn get_pair_from_str(trusted_args: &TrustedCli, account: &str) -> sr25519_core::Pair {
	info!("getting pair for {}", account);
	match &account[..2] {
		"//" => sr25519_core::Pair::from_string(account, None).unwrap(),
		"0x" => sr25519_core::Pair::from_string_with_seed(account, None).unwrap().0,
		_ => {
			if sr25519::Public::from_ss58check(account).is_err() {
				// could be mnemonic phrase
				return sr25519_core::Pair::from_string_with_seed(account, None).unwrap().0
			}
			info!("fetching from keystore at {}", &TRUSTED_KEYSTORE_PATH);
			// open store without password protection
			let store = LocalKeystore::open(get_keystore_path(trusted_args), None)
				.expect("store should exist");
			info!("store opened");
			let maybe_pair = store
				.key_pair::<sr25519::AppPair>(
					&sr25519::Public::from_ss58check(account).unwrap().into(),
				)
				.unwrap();
			drop(store);
			match maybe_pair {
				Some(pair) => pair.into(),
				None => panic!("account not in my_trusted_keystore"),
			}
		},
	}
}

// get an AccountId either form keyring (well known keys) or from the store
pub(crate) fn get_account_id_from_str(account: &str) -> AccountId {
	info!("getting AccountId for {}", account);
	match &account[..2] {
		"//" => sr25519_core::Pair::from_string(account, None).unwrap().public().into(),
		"0x" => sr25519_core::Pair::from_string_with_seed(account, None)
			.unwrap()
			.0
			.public()
			.into(),
		_ => sr25519::Public::from_ss58check(account).unwrap().into(),
	}
}
