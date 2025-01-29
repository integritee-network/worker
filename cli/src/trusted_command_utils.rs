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
	trusted_operation::perform_trusted_operation,
	Cli, CliError,
};
use base58::{FromBase58, ToBase58};
use codec::{Decode, Encode};
use ita_stf::{Getter, TrustedCallSigned, TrustedGetter};
use itc_rpc_client::direct_client::DirectApi;
use itp_rpc::{RpcRequest, RpcResponse, RpcReturnValue};
use itp_stf_primitives::types::{AccountId, KeyPair, ShardIdentifier, TrustedOperation};
use itp_types::{AccountInfo, DirectRequestStatus, EnclaveFingerprint, H256};
use itp_utils::FromHexPrefixed;
use its_primitives::types::header::SidechainHeader;
use log::*;
use sp_application_crypto::sr25519;
use sp_core::{crypto::Ss58Codec, sr25519 as sr25519_core, Pair};
use sp_runtime::traits::IdentifyAccount;
use std::{boxed::Box, path::PathBuf};
use substrate_client_keystore::LocalKeystore;

const TRUSTED_KEYSTORE_PATH: &str = "my_trusted_keystore";

#[macro_export]
macro_rules! get_basic_signing_info_from_args {
	($sender:expr, $maybe_session_proxy:expr, $cli:ident, $trusted_args:ident ) => {{
		use itp_stf_primitives::types::AccountId;
		use log::debug;
		use sp_application_crypto::Pair;
		use sp_core::crypto::Ss58Codec;
		use $crate::trusted_command_utils::{
			get_account_id_from_str, get_identifiers, get_pair_from_str,
		};

		let sender: AccountId = get_account_id_from_str($sender.as_str());
		let signer = $maybe_session_proxy
			.as_ref()
			.map(|proxy| get_pair_from_str($cli, $trusted_args, proxy.as_str()))
			.unwrap_or_else(|| get_pair_from_str($cli, $trusted_args, $sender.as_str()));
		debug!(
			"get_basic_signing_info_from_args: sender = {:?}, signer: {:?}",
			sender.to_ss58check(),
			signer.public().to_ss58check()
		);
		let (mrenclave, shard) = get_identifiers($cli, $trusted_args);
		(sender, signer, mrenclave, shard)
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

pub(crate) fn get_keystore_path(cli: &Cli, trusted_args: &TrustedCli) -> PathBuf {
	let (_mrenclave, shard) = get_identifiers(cli, trusted_args);
	PathBuf::from(&format!("{}/{}", TRUSTED_KEYSTORE_PATH, shard.encode().to_base58()))
}

pub(crate) fn get_identifiers(cli: &Cli, trusted_args: &TrustedCli) -> ([u8; 32], ShardIdentifier) {
	let mrenclave = if let Some(ref mrenclave_arg) = trusted_args.mrenclave {
		mrenclave_from_base58(mrenclave_arg)
	} else {
		warn!("no --mrenclave argument provided. Will trustfully fetch enclave fingerprint from worker rpc endpoint");
		get_fingerprint(cli).expect("could not get fingerprint").0
	};
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
pub(crate) fn get_pair_from_str(
	cli: &Cli,
	trusted_args: &TrustedCli,
	account: &str,
) -> sr25519_core::Pair {
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
			let store = LocalKeystore::open(get_keystore_path(cli, trusted_args), None)
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

pub(crate) fn get_sidechain_header(cli: &Cli) -> Result<SidechainHeader, CliError> {
	let direct_api = get_worker_api_direct(cli);
	let rpc_method = "chain_getHeader".to_owned();
	let jsonrpc_call: String = RpcRequest::compose_jsonrpc_call(rpc_method, vec![]).unwrap();
	let rpc_response_str = direct_api.get(&jsonrpc_call).unwrap();
	// Decode RPC response.
	let rpc_response: RpcResponse = serde_json::from_str(&rpc_response_str)
		.map_err(|err| CliError::WorkerRpcApi { msg: err.to_string() })?;
	let rpc_return_value = RpcReturnValue::from_hex(&rpc_response.result)
		// Replace with `inspect_err` once it's stable.
		.map_err(|err| {
			error!("Failed to decode RpcReturnValue: {:?}", err);
			CliError::WorkerRpcApi { msg: "failed to decode RpcReturnValue".to_string() }
		})?;

	if rpc_return_value.status == DirectRequestStatus::Error {
		error!("{}", String::decode(&mut rpc_return_value.value.as_slice()).unwrap());
		return Err(CliError::WorkerRpcApi { msg: "rpc error".to_string() })
	}

	SidechainHeader::decode(&mut rpc_return_value.value.as_slice())
		// Replace with `inspect_err` once it's stable.
		.map_err(|err| {
			error!("Failed to decode sidechain header: {:?}", err);
			CliError::WorkerRpcApi { msg: err.to_string() }
		})
}

pub(crate) fn get_fingerprint(cli: &Cli) -> Result<H256, CliError> {
	let direct_api = get_worker_api_direct(cli);
	let rpc_method = "author_getFingerprint".to_owned();
	let jsonrpc_call: String = RpcRequest::compose_jsonrpc_call(rpc_method, vec![]).unwrap();
	let rpc_response_str = direct_api.get(&jsonrpc_call).unwrap();
	// Decode RPC response.
	let rpc_response: RpcResponse = serde_json::from_str(&rpc_response_str)
		.map_err(|err| CliError::WorkerRpcApi { msg: err.to_string() })?;
	let rpc_return_value = RpcReturnValue::from_hex(&rpc_response.result)
		// Replace with `inspect_err` once it's stable.
		.map_err(|err| {
			error!("Failed to decode RpcReturnValue: {:?}", err);
			CliError::WorkerRpcApi { msg: "failed to decode RpcReturnValue".to_string() }
		})?;

	if rpc_return_value.status == DirectRequestStatus::Error {
		error!("{}", String::decode(&mut rpc_return_value.value.as_slice()).unwrap());
		return Err(CliError::WorkerRpcApi { msg: "rpc error".to_string() })
	}

	EnclaveFingerprint::decode(&mut rpc_return_value.value.as_slice())
		// Replace with `inspect_err` once it's stable.
		.map_err(|err| {
			error!("Failed to decode fingerprint: {:?}", err);
			CliError::WorkerRpcApi { msg: err.to_string() }
		})
}
