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

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, feature(assert_matches))]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use thiserror_sgx as thiserror;
	pub use url_sgx as url;
}

use crate::{error::Error, metrics_exporter::MetricsExporter};
use itp_ocall_api::EnclaveMetricsOCallApi;
use std::sync::Arc;

pub mod error;
pub mod metrics_exporter;
pub mod traits;
pub mod types;

pub mod oracles;
pub use oracles::{exchange_rate_oracle::ExchangeRateOracle, weather_oracle::WeatherOracle};

pub mod oracle_sources;
pub use oracle_sources::{
	coin_gecko::CoinGeckoSource, coin_market_cap::CoinMarketCapSource,
	weather_oracle_source::WeatherOracleSource,
};

#[cfg(test)]
mod mock;

#[cfg(test)]
mod test;

pub type CoinGeckoExchangeRateOracle<OCallApi> =
	ExchangeRateOracle<CoinGeckoSource, MetricsExporter<OCallApi>>;

pub type CoinMarketCapExchangeRateOracle<OCallApi> =
	ExchangeRateOracle<CoinMarketCapSource, MetricsExporter<OCallApi>>;

pub type OpenMeteoWeatherOracle<OCallApi> =
	WeatherOracle<WeatherOracleSource, MetricsExporter<OCallApi>>;

pub fn create_coin_gecko_oracle<OCallApi: EnclaveMetricsOCallApi>(
	ocall_api: Arc<OCallApi>,
) -> CoinGeckoExchangeRateOracle<OCallApi> {
	ExchangeRateOracle::new(CoinGeckoSource {}, Arc::new(MetricsExporter::new(ocall_api)))
}

pub fn create_coin_market_cap_oracle<OCallApi: EnclaveMetricsOCallApi>(
	ocall_api: Arc<OCallApi>,
) -> CoinMarketCapExchangeRateOracle<OCallApi> {
	ExchangeRateOracle::new(CoinMarketCapSource {}, Arc::new(MetricsExporter::new(ocall_api)))
}

pub fn create_open_meteo_weather_oracle<OCallApi: EnclaveMetricsOCallApi>(
	ocall_api: Arc<OCallApi>,
) -> OpenMeteoWeatherOracle<OCallApi> {
	WeatherOracle::new(WeatherOracleSource {}, Arc::new(MetricsExporter::new(ocall_api)))
}
