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

use crate::teeracle::interval_scheduling::schedule_on_repeating_intervals;
use codec::{Decode, Encode};
use itp_enclave_api::teeracle_api::TeeracleApi;
use itp_node_api::api_client::ParentchainApi;
use itp_settings::teeracle::DEFAULT_MARKET_DATA_UPDATE_INTERVAL;
use itp_utils::hex::hex_encode;
use log::*;
use sp_runtime::OpaqueExtrinsic;
use std::time::Duration;
use substrate_api_client::XtStatus;
use teeracle_metrics::{increment_number_of_request_failures, set_extrinsics_inclusion_success};
use tokio::runtime::Handle;

pub(crate) mod interval_scheduling;
pub(crate) mod teeracle_metrics;

/// Send extrinsic to chain according to the market data update interval in the settings
/// with the current market data (for now only exchange rate).
pub(crate) fn start_interval_market_update<E: TeeracleApi>(
	api: &ParentchainApi,
	maybe_interval: Option<Duration>,
	enclave_api: &E,
	tokio_handle: &Handle,
) {
	let interval = maybe_interval.unwrap_or(DEFAULT_MARKET_DATA_UPDATE_INTERVAL);
	info!("Starting teeracle interval for oracle update, interval of {:?}", interval);

	schedule_on_repeating_intervals(
		|| {
			execute_update_market(api, enclave_api, tokio_handle);
			execute_weather_update(api, enclave_api, tokio_handle);
		},
		interval,
	);
}

fn execute_weather_update<E: TeeracleApi>(
	node_api: &ParentchainApi,
	enclave: &E,
	tokio_handle: &Handle,
) {
	let updated_extrinsic = match enclave.update_weather_data_xt("54.32", "15.37") {
		Err(e) => {
			error!("{:?}", e);
			increment_number_of_request_failures();
			return
		},
		Ok(r) => r,
	};

	let extrinsics = match <Vec<OpaqueExtrinsic>>::decode(&mut updated_extrinsic.as_slice()) {
		Ok(calls) => calls,
		Err(e) => {
			error!("Failed to decode opaque extrinsics(s): {:?}: ", e);
			return
		},
	};

	extrinsics.into_iter().for_each(|call| {
		let node_api_clone = node_api.clone();
		tokio_handle.spawn(async move {
			let hex_encoded_extrinsic = hex_encode(&call.encode());
			debug!("Hex encoded extrinsic to be sent: {}", hex_encoded_extrinsic);
			println!("[>] Update oracle (send the extrinsic)");
			let extrinsic_hash =
				match node_api_clone.send_extrinsic(hex_encoded_extrinsic, XtStatus::InBlock) {
					Err(e) => {
						error!("Failed to send extrinsic: {:?}", e);
						set_extrinsics_inclusion_success(false);
						return
					},
					Ok(hash) => {
						set_extrinsics_inclusion_success(true);
						hash
					},
				};
			println!("[<] Extrinsic got included into a block. Hash: {:?}\n", extrinsic_hash);
		});
	});
}

fn execute_update_market<E: TeeracleApi>(
	node_api: &ParentchainApi,
	enclave: &E,
	tokio_handle: &Handle,
) {
	// Get market data for usd (hardcoded)
	let updated_extrinsic = match enclave.update_market_data_xt("TEER", "USD") {
		Err(e) => {
			error!("{:?}", e);
			increment_number_of_request_failures();
			return
		},
		Ok(r) => r,
	};

	let extrinsics: Vec<OpaqueExtrinsic> = match Decode::decode(&mut updated_extrinsic.as_slice()) {
		Ok(calls) => calls,
		Err(e) => {
			error!("Failed to decode opaque extrinsic(s): {:?}: ", e);
			return
		},
	};

	// Send the extrinsics to the parentchain and wait for InBlock confirmation.
	for call in extrinsics.into_iter() {
		let node_api_clone = node_api.clone();
		tokio_handle.spawn(async move {
			let hex_encoded_extrinsic = hex_encode(&call.encode());
			debug!("Hex encoded extrinsic to be sent: {}", hex_encoded_extrinsic);

			println!("[>] Update the exchange rate (send the extrinsic)");
			let extrinsic_hash =
				match node_api_clone.send_extrinsic(hex_encoded_extrinsic, XtStatus::InBlock) {
					Err(e) => {
						error!("Failed to send extrinsic: {:?}", e);
						set_extrinsics_inclusion_success(false);
						return
					},
					Ok(hash) => {
						set_extrinsics_inclusion_success(true);
						hash
					},
				};

			println!("[<] Extrinsic got included into a block. Hash: {:?}\n", extrinsic_hash);
		});
	}
}
