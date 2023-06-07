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

use crate::{error::ServiceResult, teeracle::schedule_periodic::schedule_periodic};
use codec::{Decode, Encode};
use itp_enclave_api::teeracle_api::TeeracleApi;
use itp_node_api::api_client::ParentchainApi;
use itp_types::parentchain::Hash;
use itp_utils::hex::hex_encode;
use log::*;
use sp_runtime::OpaqueExtrinsic;
use std::time::Duration;
use substrate_api_client::{SubmitAndWatch, XtStatus};
use teeracle_metrics::{increment_number_of_request_failures, set_extrinsics_inclusion_success};
use tokio::runtime::Handle;

pub(crate) mod schedule_periodic;
pub(crate) mod teeracle_metrics;

/// Schedule periodic reregistration of the enclave.
///
/// The `send_register_xt` needs to create a fresh registration extrinsic every time it is called
/// (updated nonce, fresh IAS-RA or DCAP-Quote).
///
/// Currently, this is only used for the teeracle, but could also be used for other flavors in the
/// future.
pub(crate) fn schedule_periodic_reregistration_thread(
	send_register_xt: impl Fn() -> Option<Hash> + std::marker::Send + 'static,
	period: Duration,
) {
	println!("Schedule periodic enclave reregistration every: {:?}", period);

	std::thread::Builder::new()
		.name("enclave_reregistration_thread".to_owned())
		.spawn(move || {
			schedule_periodic(
				|| {
					trace!("Reregistering the enclave.");
					if let Some(block_hash) = send_register_xt() {
						println!(
							"✅ Successfully reregistered the enclave. Block hash: {}.",
							block_hash
						)
					} else {
						error!("❌ Could not reregister the enclave.")
					}
				},
				period,
			);
		})
		.unwrap();
}

/// Executes a periodic teeracle data update and sends the new data to the parentchain.
///
/// Note: Puts the current thread to sleep for `period`.
pub(crate) fn start_periodic_market_update<E: TeeracleApi>(
	api: &ParentchainApi,
	period: Duration,
	enclave_api: &E,
	tokio_handle: &Handle,
) {
	let updates_to_run = || {
		if let Err(e) = execute_oracle_update(api, tokio_handle, || {
			// Get market data for usd (hardcoded)
			enclave_api.update_market_data_xt("TEER", "USD")
		}) {
			error!("Error running market update {:?}", e)
		}

		// TODO: Refactor and add this back according to ISSUE: https://github.com/integritee-network/worker/issues/1300
		// if let Err(e) = execute_oracle_update(api, tokio_handle, || {
		// 	enclave_api.update_weather_data_xt("54.32", "15.37")
		// }) {
		// 	error!("Error running weather update {:?}", e)
		// }
	};
	info!("Teeracle will update now");
	updates_to_run();

	info!("Schedule teeracle updates every {:?}", period);
	schedule_periodic(updates_to_run, period);
}

fn execute_oracle_update<F>(
	node_api: &ParentchainApi,
	tokio_handle: &Handle,
	get_oracle_xt: F,
) -> ServiceResult<()>
where
	F: Fn() -> Result<Vec<u8>, itp_enclave_api::error::Error>,
{
	let oracle_xt = get_oracle_xt().map_err(|e| {
		increment_number_of_request_failures();
		e
	})?;

	let extrinsics = <Vec<OpaqueExtrinsic>>::decode(&mut oracle_xt.as_slice())?;

	// Send the extrinsics to the parentchain and wait for InBlock confirmation.
	for call in extrinsics.into_iter() {
		let node_api_clone = node_api.clone();
		tokio_handle.spawn(async move {
			let encoded_extrinsic = call.encode();
			debug!("Hex encoded extrinsic to be sent: {}", hex_encode(&encoded_extrinsic));

			println!("[>] Update oracle data (send the extrinsic)");
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
