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
	command_utils::{get_chain_api, get_pair_from_str, get_shielding_key, get_worker_api_direct},
	error::{Error, Result},
	trusted_cli::TrustedCli,
	Cli,
};
use base58::{FromBase58, ToBase58};
use codec::{Decode, Encode};
use enclave_bridge_primitives::Request;
use ita_stf::{Getter, TrustedOperation};
use itc_rpc_client::direct_client::{DirectApi, DirectClient};
use itp_node_api::api_client::{ParentchainApi, ParentchainExtrinsicSigner, ENCLAVE_BRIDGE};
use itp_rpc::{RpcRequest, RpcResponse, RpcReturnValue};
use itp_sgx_crypto::ShieldingCryptoEncrypt;
use itp_stf_primitives::types::ShardIdentifier;
use itp_types::{BlockNumber, DirectRequestStatus, TrustedOperationStatus};
use itp_utils::{FromHexPrefixed, ToHexPrefixed};
use log::*;
use my_node_runtime::{Hash, RuntimeEvent};
use pallet_enclave_bridge::Event as EnclaveBridgeEvent;
use sp_core::{sr25519 as sr25519_core, H256};
use std::{
	result::Result as StdResult,
	sync::mpsc::{channel, Receiver},
	time::Instant,
};
use substrate_api_client::{
	compose_extrinsic, GetHeader, SubmitAndWatchUntilSuccess, SubscribeEvents,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum TrustedOperationError {
	#[error("extrinsic L1 error: {msg:?}")]
	Extrinsic { msg: String },
	#[error("default error: {msg:?}")]
	Default { msg: String },
}

pub(crate) type TrustedOpResult = StdResult<Option<Vec<u8>>, TrustedOperationError>;

pub(crate) fn perform_trusted_operation(
	cli: &Cli,
	trusted_args: &TrustedCli,
	top: &TrustedOperation,
) -> TrustedOpResult {
	match top {
		TrustedOperation::indirect_call(_) => send_indirect_request(cli, trusted_args, top),
		TrustedOperation::direct_call(_) => send_direct_request(cli, trusted_args, top),
		TrustedOperation::get(getter) => execute_getter_from_cli_args(cli, trusted_args, getter),
	}
}

fn execute_getter_from_cli_args(
	cli: &Cli,
	trusted_args: &TrustedCli,
	getter: &Getter,
) -> TrustedOpResult {
	let shard = read_shard(trusted_args).unwrap();
	let direct_api = get_worker_api_direct(cli);
	get_state(&direct_api, shard, getter)
}

pub(crate) fn get_state(
	direct_api: &DirectClient,
	shard: ShardIdentifier,
	getter: &Getter,
) -> TrustedOpResult {
	// Compose jsonrpc call.
	let data = Request { shard, cyphertext: getter.encode() };
	let rpc_method = "state_executeGetter".to_owned();
	let jsonrpc_call: String =
		RpcRequest::compose_jsonrpc_call(rpc_method, vec![data.to_hex()]).unwrap();

	let rpc_response_str = direct_api.get(&jsonrpc_call).unwrap();

	// Decode RPC response.
	let rpc_response: RpcResponse = serde_json::from_str(&rpc_response_str)
		.map_err(|err| TrustedOperationError::Default { msg: err.to_string() })?;
	let rpc_return_value = RpcReturnValue::from_hex(&rpc_response.result)
		// Replace with `inspect_err` once it's stable.
		.map_err(|err| {
			error!("Failed to decode RpcReturnValue: {:?}", err);
			TrustedOperationError::Default { msg: "RpcReturnValue::from_hex".to_string() }
		})?;

	if rpc_return_value.status == DirectRequestStatus::Error {
		println!("[Error] {}", String::decode(&mut rpc_return_value.value.as_slice()).unwrap());
		return Err(TrustedOperationError::Default {
			msg: "[Error] DirectRequestStatus::Error".to_string(),
		})
	}

	let maybe_state = Option::decode(&mut rpc_return_value.value.as_slice())
		// Replace with `inspect_err` once it's stable.
		.map_err(|err| {
			error!("Failed to decode return value: {:?}", err);
			TrustedOperationError::Default { msg: "Option::decode".to_string() }
		})?;

	Ok(maybe_state)
}

fn send_indirect_request(
	cli: &Cli,
	trusted_args: &TrustedCli,
	trusted_operation: &TrustedOperation,
) -> TrustedOpResult {
	let mut chain_api = get_chain_api(cli);
	let encryption_key = get_shielding_key(cli).unwrap();
	let call_encrypted = encryption_key.encrypt(&trusted_operation.encode()).unwrap();

	let shard = read_shard(trusted_args).unwrap();
	debug!(
		"invoke indirect send_request: trusted operation: {:?},  shard: {}",
		trusted_operation,
		shard.encode().to_base58()
	);
	let arg_signer = &trusted_args.xt_signer;
	let signer = get_pair_from_str(arg_signer);
	chain_api.set_signer(ParentchainExtrinsicSigner::new(sr25519_core::Pair::from(signer)));

	let request = Request { shard, cyphertext: call_encrypted };
	let xt = compose_extrinsic!(&chain_api, ENCLAVE_BRIDGE, "invoke", request);

	let block_hash = match chain_api.submit_and_watch_extrinsic_until_success(xt, false) {
		Ok(xt_report) => {
			println!(
				"[+] invoke TrustedOperation extrinsic success. extrinsic hash: {:?} / status: {:?} / block hash: {:?}",
				xt_report.extrinsic_hash, xt_report.status, xt_report.block_hash.unwrap()
			);
			xt_report.block_hash.unwrap()
		},
		Err(e) => {
			error!("invoke TrustedOperation extrinsic failed {:?}", e);
			return Err(TrustedOperationError::Extrinsic { msg: format!("{:?}", e) })
		},
	};

	info!(
		"Trusted call extrinsic sent for shard {} and successfully included in parentchain block with hash {:?}.",
		shard.encode().to_base58(), block_hash
	);
	info!("Waiting for execution confirmation from enclave...");
	let mut subscription = chain_api.subscribe_events().unwrap();
	loop {
		let event_records = subscription.next_event::<RuntimeEvent, Hash>().unwrap().unwrap();
		for event_record in event_records {
			if let RuntimeEvent::EnclaveBridge(EnclaveBridgeEvent::ProcessedParentchainBlock {
				shard,
				block_hash: confirmed_block_hash,
				trusted_calls_merkle_root,
				block_number: confirmed_block_number,
			}) = event_record.event
			{
				info!("Confirmation of ProcessedParentchainBlock received");
				debug!("shard: {:?}", shard);
				debug!("confirmed parentchain block Hash: {:?}", block_hash);
				debug!("trusted calls merkle root: {:?}", trusted_calls_merkle_root);
				debug!("Confirmed stf block Hash: {:?}", confirmed_block_hash);
				if let Err(e) = check_if_received_event_exceeds_expected(
					&chain_api,
					block_hash,
					confirmed_block_hash,
					confirmed_block_number,
				) {
					error!("ProcessedParentchainBlock event: {:?}", e);
					return Err(TrustedOperationError::Default {
						msg: format!("ProcessedParentchainBlock event: {:?}", e),
					})
				};

				if confirmed_block_hash == block_hash {
					return Ok(Some(block_hash.encode()))
				}
			}
		}
	}
}

fn check_if_received_event_exceeds_expected(
	chain_api: &ParentchainApi,
	block_hash: Hash,
	confirmed_block_hash: Hash,
	confirmed_block_number: BlockNumber,
) -> Result<()> {
	let block_number = chain_api.get_header(Some(block_hash))?.ok_or(Error::MissingBlock)?.number;

	info!("Expected block Number: {:?}", block_number);
	info!("Confirmed block Number: {:?}", confirmed_block_number);
	// The returned block number belongs to a subsequent event. We missed our event and can break the loop.
	if confirmed_block_number > block_number {
		return Err(Error::ConfirmedBlockNumberTooHigh(confirmed_block_number, block_number))
	}
	// The block number is correct, but the block hash does not fit.
	if block_number == confirmed_block_number && block_hash != confirmed_block_hash {
		return Err(Error::ConfirmedBlockHashDoesNotMatchExpected(confirmed_block_hash, block_hash))
	}
	Ok(())
}

pub fn read_shard(trusted_args: &TrustedCli) -> StdResult<ShardIdentifier, codec::Error> {
	match &trusted_args.shard {
		Some(s) => match s.from_base58() {
			Ok(s) => ShardIdentifier::decode(&mut &s[..]),
			_ => panic!("shard argument must be base58 encoded"),
		},
		None => match trusted_args.mrenclave.from_base58() {
			Ok(s) => ShardIdentifier::decode(&mut &s[..]),
			_ => panic!("mrenclave argument must be base58 encoded"),
		},
	}
}

/// sends a rpc watch request to the worker api server
fn send_direct_request(
	cli: &Cli,
	trusted_args: &TrustedCli,
	operation_call: &TrustedOperation,
) -> TrustedOpResult {
	let encryption_key = get_shielding_key(cli).unwrap();
	let shard = read_shard(trusted_args).unwrap();
	let jsonrpc_call: String = get_json_request(shard, operation_call, encryption_key);
	debug!(
		"send_direct_request: trusted operation: {:?},  shard: {}",
		operation_call,
		shard.encode().to_base58()
	);
	let direct_api = get_worker_api_direct(cli);

	debug!("setup sender and receiver");
	let (sender, receiver) = channel();
	direct_api.watch(jsonrpc_call, sender);

	debug!("waiting for rpc response");
	loop {
		match receiver.recv() {
			Ok(response) => {
				debug!("received response");
				let response: RpcResponse = serde_json::from_str(&response).unwrap();
				if let Ok(return_value) = RpcReturnValue::from_hex(&response.result) {
					debug!("successfully decoded rpc response: {:?}", return_value);
					match return_value.status {
						DirectRequestStatus::Error => {
							debug!("request status is error");
							if let Ok(value) = String::decode(&mut return_value.value.as_slice()) {
								println!("[Error] {}", value);
							}
							direct_api.close().unwrap();
							return Err(TrustedOperationError::Default {
								msg: "[Error] DirectRequestStatus::Error".to_string(),
							})
						},
						DirectRequestStatus::TrustedOperationStatus(status) => {
							debug!("request status is: {:?}", status);
							if let Ok(value) = Hash::decode(&mut return_value.value.as_slice()) {
								println!("Trusted call {:?} is {:?}", value, status);
							}
							if connection_can_be_closed(status) {
								direct_api.close().unwrap();
								return Ok(None)
							}
						},
						DirectRequestStatus::Ok => {
							debug!("request status is ignored");
							direct_api.close().unwrap();
							return Ok(None)
						},
					}
					if !return_value.do_watch {
						debug!("do watch is false, closing connection");
						direct_api.close().unwrap();
						return Ok(None)
					}
				};
			},
			Err(e) => {
				error!("failed to receive rpc response: {:?}", e);
				direct_api.close().unwrap();
				return Err(TrustedOperationError::Default {
					msg: "failed to receive rpc response".to_string(),
				})
			},
		};
	}
}

pub(crate) fn get_json_request(
	shard: ShardIdentifier,
	operation_call: &TrustedOperation,
	shielding_pubkey: sgx_crypto_helper::rsa3072::Rsa3072PubKey,
) -> String {
	let operation_call_encrypted = shielding_pubkey.encrypt(&operation_call.encode()).unwrap();

	// compose jsonrpc call
	let request = Request { shard, cyphertext: operation_call_encrypted };
	RpcRequest::compose_jsonrpc_call(
		"author_submitAndWatchExtrinsic".to_string(),
		vec![request.to_hex()],
	)
	.unwrap()
}

pub(crate) fn wait_until(
	receiver: &Receiver<String>,
	until: impl Fn(TrustedOperationStatus) -> bool,
) -> Option<(H256, Instant)> {
	debug!("waiting for rpc response");
	loop {
		match receiver.recv() {
			Ok(response) => {
				debug!("received response: {}", response);
				let parse_result: StdResult<RpcResponse, _> = serde_json::from_str(&response);
				if let Ok(response) = parse_result {
					if let Ok(return_value) = RpcReturnValue::from_hex(&response.result) {
						debug!("successfully decoded rpc response: {:?}", return_value);
						match return_value.status {
							DirectRequestStatus::Error => {
								debug!("request status is error");
								if let Ok(value) =
									String::decode(&mut return_value.value.as_slice())
								{
									println!("[Error] {}", value);
								}
								return None
							},
							DirectRequestStatus::TrustedOperationStatus(status) => {
								debug!("request status is: {:?}", status);
								if let Ok(value) = Hash::decode(&mut return_value.value.as_slice())
								{
									println!("Trusted call {:?} is {:?}", value, status);
									if until(status.clone()) {
										return Some((value, Instant::now()))
									} else if status == TrustedOperationStatus::Invalid {
										error!("Invalid request");
										return None
									}
								}
							},
							DirectRequestStatus::Ok => {
								debug!("request status is ignored");
								return None
							},
						}
					};
				} else {
					error!("Could not parse response");
				};
			},
			Err(e) => {
				error!("failed to receive rpc response: {:?}", e);
				return None
			},
		};
	}
}

fn connection_can_be_closed(top_status: TrustedOperationStatus) -> bool {
	!matches!(
		top_status,
		TrustedOperationStatus::Submitted
			| TrustedOperationStatus::Future
			| TrustedOperationStatus::Ready
			| TrustedOperationStatus::Broadcast
	)
}
