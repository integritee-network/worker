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
	trusted_cli::TrustedCli,
	Cli,
};
use base58::{FromBase58, ToBase58};
use codec::{Decode, Encode, Input};
use enclave_bridge_primitives::Request;
use ita_stf::{Getter, TrustedCallSigned};
use itc_rpc_client::direct_client::{DirectApi, DirectClient};
use itp_node_api::api_client::{ApiClientError, ENCLAVE_BRIDGE};
use itp_rpc::{RpcRequest, RpcResponse, RpcReturnValue, RpcSubscriptionUpdate};
use itp_sgx_crypto::ShieldingCryptoEncrypt;
use itp_stf_primitives::types::{ShardIdentifier, TrustedOperation};
use itp_types::{
	parentchain::{BlockHash, BlockNumber, ProcessedParentchainBlock},
	DirectRequestStatus, TrustedOperationStatus,
};
use itp_utils::{FromHexPrefixed, ToHexPrefixed};
use log::*;

use crate::trusted_command_utils::get_identifiers;
use itp_types::parentchain::Hash;
use sp_core::H256;
use std::{
	fmt::Debug,
	result::Result as StdResult,
	sync::mpsc::{channel, Receiver},
};
use substrate_api_client::{
	ac_compose_macros::compose_extrinsic, GetChainInfo, SubmitAndWatch, SubscribeEvents, XtStatus,
};
use thiserror::Error;

const TIMEOUT_BLOCKS: BlockNumber = 10;

#[derive(Debug, Error)]
pub(crate) enum TrustedOperationError {
	#[error("{0:?}")]
	ApiClient(ApiClientError),
	#[error("Could not retrieve Header from node")]
	MissingBlock,
	#[error("confirmation timed out after ({0:?}) blocks")]
	ConfirmationTimedOut(BlockNumber),
	#[error("Confirmed Block Number ({0:?}) exceeds expected one ({0:?})")]
	ConfirmedBlockNumberTooHigh(
		itp_types::parentchain::BlockNumber,
		itp_types::parentchain::BlockNumber,
	),
	#[error("Confirmed Block Hash ({0:?}) does not match expected one ({0:?})")]
	ConfirmedBlockHashDoesNotMatchExpected(BlockHash, BlockHash),
	#[error("invocation extrinsic L1 error: {msg:?}")]
	IndirectInvocationFailed { msg: String },
	#[error("default error: {msg:?}")]
	Default { msg: String },
}

pub(crate) fn into_default_trusted_op_err(err_msg: impl ToString) -> TrustedOperationError {
	TrustedOperationError::Default { msg: err_msg.to_string() }
}

impl From<ApiClientError> for TrustedOperationError {
	fn from(error: ApiClientError) -> Self {
		Self::ApiClient(error)
	}
}

pub(crate) type TrustedOpResult<T> = StdResult<T, TrustedOperationError>;

pub(crate) fn perform_trusted_operation<T: Decode + Debug>(
	cli: &Cli,
	trusted_args: &TrustedCli,
	top: &TrustedOperation<TrustedCallSigned, Getter>,
) -> TrustedOpResult<T> {
	match top {
		TrustedOperation::indirect_call(_) => send_indirect_request::<T>(cli, trusted_args, top),
		TrustedOperation::get(getter) =>
			execute_getter_from_cli_args::<T>(cli, trusted_args, getter),
		TrustedOperation::direct_call(_) => Err(TrustedOperationError::Default {
			msg: "Invalid call to `perform_trusted_operation`, use `send_direct_request` directly"
				.into(),
		}),
	}
}

fn execute_getter_from_cli_args<T: Decode + Debug>(
	cli: &Cli,
	trusted_args: &TrustedCli,
	getter: &Getter,
) -> TrustedOpResult<T> {
	let (_, shard) = get_identifiers(cli, trusted_args);
	let direct_api = get_worker_api_direct(cli);
	get_state(&direct_api, shard, getter)
}

pub(crate) fn get_state<T: Decode + Debug>(
	direct_api: &DirectClient,
	shard: ShardIdentifier,
	getter: &Getter,
) -> TrustedOpResult<T> {
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
		error!("{}", String::decode(&mut rpc_return_value.value.as_slice()).unwrap());
		return Err(TrustedOperationError::Default {
			msg: "[Error] DirectRequestStatus::Error".to_string(),
		})
	}

	let maybe_state: Option<Vec<u8>> = Option::decode(&mut rpc_return_value.value.as_slice())
		// Replace with `inspect_err` once it's stable.
		.map_err(|err| {
			error!("Failed to decode return value: {:?}", err);
			TrustedOperationError::Default { msg: "Option::decode".to_string() }
		})?;

	match maybe_state {
		Some(state) => {
			let decoded = decode_response_value(&mut state.as_slice())?;
			Ok(decoded)
		},
		None => Err(TrustedOperationError::Default { msg: "Value not present".to_string() }),
	}
}

fn send_indirect_request<T: Decode + Debug>(
	cli: &Cli,
	trusted_args: &TrustedCli,
	trusted_operation: &TrustedOperation<TrustedCallSigned, Getter>,
) -> TrustedOpResult<T> {
	let mut chain_api = get_chain_api(cli);
	let encryption_key = get_shielding_key(cli).unwrap();
	let call_encrypted = encryption_key.encrypt(&trusted_operation.encode()).unwrap();

	let (_, shard) = get_identifiers(cli, trusted_args);
	debug!(
		"invoke indirect send_request: trusted operation: {:?},  shard: {}",
		trusted_operation,
		shard.encode().to_base58()
	);
	let arg_signer = &trusted_args.xt_signer;
	let signer = get_pair_from_str(arg_signer);
	chain_api.set_signer(signer.into());

	let request = Request { shard, cyphertext: call_encrypted };
	let xt = compose_extrinsic!(&chain_api, ENCLAVE_BRIDGE, "invoke", request);

	let invocation_block_hash = match chain_api
		.submit_and_watch_extrinsic_until(xt, XtStatus::InBlock)
	{
		Ok(xt_report) => {
			println!(
				"[+] invoke TrustedOperation extrinsic success. extrinsic hash: {:?} / status: {:?} / block hash: {:?}",
				xt_report.extrinsic_hash, xt_report.status, xt_report.block_hash.unwrap()
			);
			xt_report.block_hash.unwrap()
		},
		Err(e) => {
			error!("invoke TrustedOperation extrinsic failed {:?}", e);
			return Err(TrustedOperationError::IndirectInvocationFailed { msg: format!("{:?}", e) })
		},
	};
	let invocation_block_number = chain_api
		.get_header(Some(invocation_block_hash))?
		.ok_or(TrustedOperationError::MissingBlock)?
		.number;
	info!(
		"Trusted call extrinsic sent for shard {} and successfully included in parentchain block {} with hash {:?}.",
		shard.encode().to_base58(), invocation_block_number, invocation_block_hash
	);
	info!("Waiting for execution confirmation from enclave...");
	let mut blocks = 0u32;
	let mut subscription = chain_api.subscribe_events().unwrap();
	loop {
		let events = subscription.next_events_from_metadata().unwrap().unwrap();
		blocks += 1;
		if blocks > TIMEOUT_BLOCKS {
			return Err(TrustedOperationError::ConfirmationTimedOut(blocks))
		}
		for event in events.iter() {
			let event = event.unwrap();
			match event.pallet_name() {
				"EnclaveBridge" => match event.variant_name() {
					"ProcessedParentchainBlock" => {
						if let Ok(Some(ev)) = event.as_event::<ProcessedParentchainBlock>() {
							println!("EnclaveBridge::{:?}", ev);
							debug!(
								"Invocation block Number we're waiting for: {:?}",
								invocation_block_number
							);
							debug!("Confirmed block Number: {:?}", ev.block_number);
							// The returned block number belongs to a subsequent event. We missed our event and can break the loop.
							if ev.block_number > invocation_block_number {
								return Err(TrustedOperationError::ConfirmedBlockNumberTooHigh(
									ev.block_number,
									invocation_block_number,
								))
							}
							// The block number is correct, but the block hash does not fit.
							if invocation_block_number == ev.block_number
								&& invocation_block_hash != ev.block_hash
							{
								return Err(
									TrustedOperationError::ConfirmedBlockHashDoesNotMatchExpected(
										ev.block_hash,
										invocation_block_hash,
									),
								)
							}
							if ev.block_hash == invocation_block_hash {
								let value = decode_response_value(
									&mut invocation_block_hash.encode().as_slice(),
								)?;
								return Ok(value)
							}
						}
					},
					_ => continue,
				},
				_ => continue,
			}
		}
	}
}

/// sends a rpc watch request to the worker api server
pub(crate) fn send_direct_request(
	cli: &Cli,
	trusted_args: &TrustedCli,
	operation_call: &TrustedOperation<TrustedCallSigned, Getter>,
) -> TrustedOpResult<Hash> {
	if !matches!(operation_call, TrustedOperation::direct_call(_)) {
		return Err(TrustedOperationError::Default {
			msg: "can only use direct_calls in this function".into(),
		})
	}
	let encryption_key = get_shielding_key(cli).unwrap();
	let (_, shard) = get_identifiers(cli, trusted_args);
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

	// the first response of `submitAndWatch` is just the plain top hash
	let top_hash = await_subscription_response(&receiver).map_err(|e| {
		error!("Error getting subscription response: {:?}", e);
		direct_api.close().unwrap();
		e
	})?;

	debug!("subscribing to updates for top with hash: {top_hash:?}");

	match await_status(&receiver, connection_can_be_closed) {
		Ok((_hash, status)) => {
			debug!("Trusted operation reached status {status:?}");
			direct_api.close().unwrap();
			Ok(top_hash)
		},
		Err(e) => {
			error!("Error submitting top: {e:?}");
			direct_api.close().unwrap();
			Err(e)
		},
	}
}

pub(crate) fn await_status(
	receiver: &Receiver<String>,
	wait_until: impl Fn(TrustedOperationStatus) -> bool,
) -> TrustedOpResult<(Hash, TrustedOperationStatus)> {
	loop {
		debug!("waiting for update");
		let (subscription_update, direct_request_status) =
			await_status_update(receiver).map_err(|e| {
				error!("Error getting status update: {:?}", e);
				e
			})?;

		debug!("successfully decoded request status: {:?}", direct_request_status);
		match direct_request_status {
			DirectRequestStatus::Error => {
				let err = subscription_update.params.error.unwrap_or("{}".into());
				debug!("request status is error");
				return Err(into_default_trusted_op_err(format!(
					"[Error] DirectRequestStatus::Error: {err}"
				)))
			},
			DirectRequestStatus::TrustedOperationStatus(status) => {
				debug!("request status is: {:?}", status);
				let hash =
					Hash::from_hex(&subscription_update.params.subscription).map_err(|e| {
						into_default_trusted_op_err(format!("Invalid subscription top hash: {e:?}"))
					})?;

				println!("Trusted call {:?} is {:?}", hash, status);

				if is_cancelled(status) {
					debug!("trusted call has been cancelled");
					return Ok((hash, status))
				}

				if wait_until(status) {
					return Ok((hash, status))
				}
			},
			DirectRequestStatus::Ok => {
				// Todo: #1625. When sending `author_submitAndWatchExtrinsic` this can never happen.
				// our cli tries to do too much in one method, we should have better separation of
				// concerns.
				panic!("`DirectRequestStatus::Ok` should never occur with `author_submitAndWatchExtrinsic`.\
				This is a bug in the usage of the cli.");
			},
		}
	}
}

pub(crate) fn await_subscription_response(receiver: &Receiver<String>) -> TrustedOpResult<H256> {
	let response_string = receiver.recv().map_err(|e| {
		into_default_trusted_op_err(format!("failed to receive rpc response: {e:?}"))
	})?;

	let response: RpcResponse = serde_json::from_str(&response_string).map_err(|e| {
		into_default_trusted_op_err(format!("Error deserializing RpcResponse: {e:?}"))
	})?;

	let top_hash = Hash::from_hex(&response.result)
		.map_err(|e| into_default_trusted_op_err(format!("Error decoding top hash: {e:?}")))?;

	Ok(top_hash)
}

pub(crate) fn await_status_update(
	receiver: &Receiver<String>,
) -> TrustedOpResult<(RpcSubscriptionUpdate, DirectRequestStatus)> {
	let response = receiver.recv().map_err(|e| {
		into_default_trusted_op_err(format!("error receiving subscription update: {e:?}"))
	})?;
	debug!("received subscription update");

	let subscription_update: RpcSubscriptionUpdate =
		serde_json::from_str(&response).map_err(|e| {
			into_default_trusted_op_err(format!("error deserializing subscription update: {e:?}"))
		})?;

	trace!("successfully decoded subscription update: {:?}", subscription_update);

	let direct_request_status = DirectRequestStatus::from_hex(&subscription_update.params.result)
		.map_err(|e| {
		into_default_trusted_op_err(format!("Error decoding direct_request_status: {e:?}"))
	})?;

	Ok((subscription_update, direct_request_status))
}

fn decode_response_value<T: Decode, I: Input>(
	value: &mut I,
) -> StdResult<T, TrustedOperationError> {
	T::decode(value).map_err(|e| TrustedOperationError::Default {
		msg: format!("Could not decode result value: {:?}", e),
	})
}

pub(crate) fn get_json_request(
	shard: ShardIdentifier,
	operation_call: &TrustedOperation<TrustedCallSigned, Getter>,
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

fn connection_can_be_closed(top_status: TrustedOperationStatus) -> bool {
	use TrustedOperationStatus::*;
	!matches!(top_status, Submitted | Future | Ready | Broadcast)
}

fn is_cancelled(top_status: TrustedOperationStatus) -> bool {
	use TrustedOperationStatus::*;
	matches!(top_status, Invalid | Usurped | Dropped | Retracted)
}
