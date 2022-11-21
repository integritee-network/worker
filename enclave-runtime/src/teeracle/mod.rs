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
	error::{Error, Result},
	initialization::global_components::GLOBAL_OCALL_API_COMPONENT,
	utils::{
		get_extrinsic_factory_from_solo_or_parachain,
		get_node_metadata_repository_from_solo_or_parachain,
	},
};
use codec::{Decode, Encode};
use core::slice;
use ita_exchange_oracle::{
	create_coin_gecko_oracle, create_coin_market_cap_oracle,
	exchange_rate_oracle::{ExchangeRateOracle, OracleSource},
	metrics_exporter::ExportMetrics,
	types::TradingPair,
	GetExchangeRate,
};
use itp_component_container::ComponentGetter;
use itp_extrinsics_factory::CreateExtrinsics;
use itp_node_api::metadata::{pallet_teeracle::TeeracleCallIndexes, provider::AccessNodeMetadata};
use itp_types::OpaqueCall;
use itp_utils::write_slice_and_whitespace_pad;
use log::*;
use sgx_types::sgx_status_t;
use sp_runtime::OpaqueExtrinsic;
use std::{string::String, vec::Vec};

/// For now get the crypto/fiat currency exchange rate from coingecko and CoinMarketCap.
#[no_mangle]
pub unsafe extern "C" fn update_market_data_xt(
	crypto_currency_ptr: *const u8,
	crypto_currency_size: u32,
	fiat_currency_ptr: *const u8,
	fiat_currency_size: u32,
	unchecked_extrinsic: *mut u8,
	unchecked_extrinsic_size: u32,
) -> sgx_status_t {
	let mut crypto_currency_slice =
		slice::from_raw_parts(crypto_currency_ptr, crypto_currency_size as usize);
	let crypto_currency: String = Decode::decode(&mut crypto_currency_slice).unwrap();

	let mut fiat_currency_slice =
		slice::from_raw_parts(fiat_currency_ptr, fiat_currency_size as usize);
	let fiat_currency: String = Decode::decode(&mut fiat_currency_slice).unwrap();

	let extrinsics = match update_market_data_internal(crypto_currency, fiat_currency) {
		Ok(xts) => xts,
		Err(e) => {
			error!("Update market data failed: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	if extrinsics.is_empty() {
		error!("Updating market data yielded no extrinsics");
		return sgx_status_t::SGX_ERROR_UNEXPECTED
	}
	let extrinsic_slice =
		slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);

	// Save created extrinsic as slice in the return value unchecked_extrinsic.
	if let Err(e) = write_slice_and_whitespace_pad(extrinsic_slice, extrinsics.encode()) {
		error!("Copying encoded extrinsics into return slice failed: {:?}", e);
		return sgx_status_t::SGX_ERROR_UNEXPECTED
	}

	sgx_status_t::SGX_SUCCESS
}

fn update_market_data_internal(
	crypto_currency: String,
	fiat_currency: String,
) -> Result<Vec<OpaqueExtrinsic>> {
	let extrinsics_factory = get_extrinsic_factory_from_solo_or_parachain()?;
	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;

	let mut extrinsic_calls: Vec<OpaqueCall> = Vec::new();

	// Get the exchange rate
	let trading_pair = TradingPair { crypto_currency, fiat_currency };

	let coin_gecko_oracle = create_coin_gecko_oracle(ocall_api.clone());

	match get_exchange_rate(trading_pair.clone(), coin_gecko_oracle) {
		Ok(opaque_call) => extrinsic_calls.push(opaque_call),
		Err(e) => {
			error!("[-] Failed to get the newest exchange rate from CoinGecko. {:?}", e);
		},
	};

	let coin_market_cap_oracle = create_coin_market_cap_oracle(ocall_api);
	match get_exchange_rate(trading_pair, coin_market_cap_oracle) {
		Ok(oc) => extrinsic_calls.push(oc),
		Err(e) => {
			error!("[-] Failed to get the newest exchange rate from CoinMarketCap. {:?}", e);
		},
	};

	let extrinsics = extrinsics_factory.create_extrinsics(extrinsic_calls.as_slice(), None)?;
	Ok(extrinsics)
}

fn get_exchange_rate<OracleSourceType, MetricsExporter>(
	trading_pair: TradingPair,
	oracle: ExchangeRateOracle<OracleSourceType, MetricsExporter>,
) -> Result<OpaqueCall>
where
	OracleSourceType: OracleSource,
	MetricsExporter: ExportMetrics,
{
	let (rate, base_url) = oracle
		.get_exchange_rate(trading_pair.clone())
		.map_err(|e| Error::Other(e.into()))?;

	let source_base_url = base_url.as_str();

	println!(
		"Update the exchange rate:  {} = {:?} for source {}",
		trading_pair.clone().key(),
		rate,
		source_base_url,
	);

	let node_metadata_repository = get_node_metadata_repository_from_solo_or_parachain()?;

	let call_ids = node_metadata_repository
		.get_from_metadata(|m| m.update_exchange_rate_call_indexes())
		.map_err(Error::NodeMetadataProvider)?
		.map_err(|e| Error::Other(format!("{:?}", e).into()))?;

	let call = OpaqueCall::from_tuple(&(
		call_ids,
		source_base_url.as_bytes().to_vec(),
		trading_pair.key().as_bytes().to_vec(),
		Some(rate),
	));

	Ok(call)
}
