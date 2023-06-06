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
	error::{Error, ServiceResult},
	teeracle::interval_scheduling::schedule_on_repeating_intervals,
};
use codec::{Decode, Encode};
use itp_enclave_api::teeracle_api::TeeracleApi;
use itp_node_api::api_client::ParentchainApi;
use itp_utils::hex::hex_encode;
use log::*;
use sp_runtime::OpaqueExtrinsic;
use std::time::Duration;
use substrate_api_client::{SubmitAndWatch, XtStatus};
use teeracle_metrics::{increment_number_of_request_failures, set_extrinsics_inclusion_success};
use tokio::runtime::Handle;

pub(crate) mod interval_scheduling;
pub(crate) mod teeracle_metrics;

/// Send extrinsic to chain according to the market data update interval in the settings
/// with the current market data (for now only exchange rate).
pub(crate) fn start_interval_market_update<E: TeeracleApi>(
	api: &ParentchainApi,
	interval: Duration,
	enclave_api: &E,
	tokio_handle: &Handle,
) {
	let updates_to_run = || {
		if let Err(e) = execute_market_update(api, enclave_api, tokio_handle) {
			error!("Error running teeracle update {:?}", e)
		}

		// TODO: Refactor and add this back according to ISSUE: https://github.com/integritee-network/worker/issues/1300
		// execute_weather_update(api, enclave_api, tokio_handle);
	};
	info!("Teeracle will update now");
	updates_to_run();

	info!("Starting teeracle interval for oracle update, interval of {:?}", interval);
	schedule_on_repeating_intervals(updates_to_run, interval);
}

#[allow(dead_code)]
fn execute_weather_update<E: TeeracleApi>(
	node_api: &ParentchainApi,
	enclave: &E,
	tokio_handle: &Handle,
) -> ServiceResult<()> {
	let updated_extrinsic = enclave.update_weather_data_xt("54.32", "15.37").map_err(|e| {
		increment_number_of_request_failures();
		Error::Custom(format!("{:?}", e).into())
	})?;

	let extrinsics = <Vec<OpaqueExtrinsic>>::decode(&mut updated_extrinsic.as_slice())?;

	extrinsics.into_iter().for_each(|call| {
		let node_api_clone = node_api.clone();
		tokio_handle.spawn(async move {
			let encoded_extrinsic = call.encode();
			debug!("Hex encoded extrinsic to be sent: {}", hex_encode(&encoded_extrinsic));
			println!("[>] Update oracle (send the extrinsic)");
			let extrinsic_hash = match node_api_clone.submit_and_watch_opaque_extrinsic_until(
				encoded_extrinsic.into(),
				XtStatus::InBlock,
			) {
				Err(e) => {
					error!("Failed to send extrinsic: {:?}", e);
					set_extrinsics_inclusion_success(false);
					return
				},
				Ok(report) => {
					set_extrinsics_inclusion_success(true);
					report.extrinsic_hash
				},
			};
			println!("[<] Extrinsic got included into a block. Hash: {:?}\n", extrinsic_hash);
		});
	});

	Ok(())
}

fn execute_market_update<E: TeeracleApi>(
	node_api: &ParentchainApi,
	enclave: &E,
	tokio_handle: &Handle,
) -> ServiceResult<()> {
	// Get market data for usd (hardcoded)
	let updated_extrinsic = enclave.update_market_data_xt("TEER", "USD").map_err(|e| {
		increment_number_of_request_failures();
		Error::Custom(format!("{:?}", e).into())
	})?;

	let extrinsics = <Vec<OpaqueExtrinsic>>::decode(&mut updated_extrinsic.as_slice())?;

	// Send the extrinsics to the parentchain and wait for InBlock confirmation.
	for call in extrinsics.into_iter() {
		let node_api_clone = node_api.clone();
		tokio_handle.spawn(async move {
			let encoded_extrinsic = call.encode();
			debug!("Hex encoded extrinsic to be sent: {}", hex_encode(&encoded_extrinsic));

			println!("[>] Update the exchange rate (send the extrinsic)");
			let extrinsic_hash = match node_api_clone.submit_and_watch_opaque_extrinsic_until(
				encoded_extrinsic.into(),
				XtStatus::InBlock,
			) {
				Err(e) => {
					error!("Failed to send extrinsic: {:?}", e);
					set_extrinsics_inclusion_success(false);
					return
				},
				Ok(report) => {
					set_extrinsics_inclusion_success(true);
					report.extrinsic_hash
				},
			};

			println!("[<] Extrinsic got included into a block. Hash: {:?}\n", extrinsic_hash);
		});
	}

	Ok(())
}
