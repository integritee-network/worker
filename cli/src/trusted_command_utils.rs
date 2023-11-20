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
	command_utils::{get_worker_api_direct, mrenclave_from_base58},
	trusted_cli::TrustedCli,
	trusted_operation::{perform_trusted_operation, read_shard},
	Cli,
};
use base58::{FromBase58, ToBase58};
use codec::{Decode, Encode};
use ita_stf::{Getter, TrustedCallSigned, TrustedGetter};
use itc_rpc_client::direct_client::DirectApi;
use itp_rpc::{RpcRequest, RpcResponse, RpcReturnValue};
use itp_stf_primitives::types::{AccountId, KeyPair, ShardIdentifier, TrustedOperation};
use itp_types::DirectRequestStatus;
use itp_utils::{FromHexPrefixed, ToHexPrefixed};
use log::*;
use my_node_runtime::Balance;
use sp_application_crypto::sr25519;
use sp_core::{crypto::Ss58Codec, sr25519 as sr25519_core, Pair};
use sp_runtime::traits::IdentifyAccount;
use std::{boxed::Box, path::PathBuf};
use substrate_client_keystore::LocalKeystore;

#[macro_export]
macro_rules! get_layer_two_nonce {
	($signer_pair:ident, $cli: ident, $trusted_args:ident ) => {{
		use ita_stf::{Getter, TrustedCallSigned, TrustedGetter};
		use $crate::trusted_command_utils::get_pending_trusted_calls_for;
		let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::trusted(
			TrustedGetter::nonce($signer_pair.public().into())
				.sign(&KeyPair::Sr25519(Box::new($signer_pair.clone()))),
		));
		// final nonce = current system nonce + pending tx count, panic early
		let nonce = perform_trusted_operation::<Index>($cli, $trusted_args, &top)
			.ok()
			.unwrap_or_default();
		debug!("got system nonce: {:?}", nonce);
		let pending_tx_count =
			get_pending_trusted_calls_for($cli, $trusted_args, &$signer_pair.public().into()).len();
		let pending_tx_count = Index::try_from(pending_tx_count).unwrap();
		debug!("got pending tx count: {:?}", pending_tx_count);
		nonce + pending_tx_count
	}};
}

const TRUSTED_KEYSTORE_PATH: &str = "my_trusted_keystore";

pub(crate) fn get_balance(cli: &Cli, trusted_args: &TrustedCli, arg_who: &str) -> Option<u128> {
	debug!("arg_who = {:?}", arg_who);
	let who = get_pair_from_str(trusted_args, arg_who);
	let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::trusted(
		TrustedGetter::free_balance(who.public().into()).sign(&KeyPair::Sr25519(Box::new(who))),
	));
	perform_trusted_operation::<Balance>(cli, trusted_args, &top).ok()
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
		_ => {
			info!("fetching from keystore at {}", &TRUSTED_KEYSTORE_PATH);
			// open store without password protection
			let store = LocalKeystore::open(get_keystore_path(trusted_args), None)
				.expect("store should exist");
			info!("store opened");
			let public_key = &sr25519::AppPublic::from_ss58check(account).unwrap();
			info!("public_key: {:?}", &public_key);
			let _pair = store.key_pair::<sr25519::AppPair>(public_key).unwrap().unwrap();
			info!("key pair fetched");
			drop(store);
			_pair.into()
		},
	}
}

// helper method to get the pending trusted calls for a given account via direct RPC
pub(crate) fn get_pending_trusted_calls_for(
	cli: &Cli,
	trusted_args: &TrustedCli,
	who: &AccountId,
) -> Vec<TrustedOperation<TrustedCallSigned, Getter>> {
	let shard = read_shard(trusted_args).unwrap();
	let direct_api = get_worker_api_direct(cli);
	let rpc_method = "author_pendingTrustedCallsFor".to_owned();
	let jsonrpc_call: String = RpcRequest::compose_jsonrpc_call(
		rpc_method,
		vec![shard.encode().to_base58(), who.to_hex()],
	)
	.unwrap();

	let rpc_response_str = direct_api.get(&jsonrpc_call).unwrap();
	let rpc_response: RpcResponse = serde_json::from_str(&rpc_response_str).unwrap();
	let rpc_return_value = RpcReturnValue::from_hex(&rpc_response.result).unwrap();

	if rpc_return_value.status == DirectRequestStatus::Error {
		println!("[Error] {}", String::decode(&mut rpc_return_value.value.as_slice()).unwrap());
		direct_api.close().unwrap();
		return vec![]
	}

	direct_api.close().unwrap();
	Decode::decode(&mut rpc_return_value.value.as_slice()).unwrap_or_default()
}
