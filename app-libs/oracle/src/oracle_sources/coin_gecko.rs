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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{
	error::Error,
	traits::OracleSource,
	types::{ExchangeRate, TradingInfo, TradingPair},
};
use itc_rest_client::{
	http_client::{HttpClient, SendWithCertificateVerification},
	rest_client::RestClient,
	RestGet, RestPath,
};
use lazy_static::lazy_static;
use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::{
	collections::HashMap,
	string::{String, ToString},
	time::Duration,
	vec::Vec,
};
use url::Url;

const COINGECKO_URL: &str = "https://api.coingecko.com";
const COINGECKO_PARAM_CURRENCY: &str = "vs_currency";
const COINGECKO_PARAM_COIN: &str = "ids";
const COINGECKO_PATH: &str = "api/v3/coins/markets";
const COINGECKO_TIMEOUT: Duration = Duration::from_secs(20u64);
const COINGECKO_ROOT_CERTIFICATE: &str = include_str!("../certificates/lets_encrypt_root_cert.pem");

lazy_static! {
	static ref SYMBOL_ID_MAP: HashMap<&'static str, &'static str> = HashMap::from([
		("DOT", "polkadot"),
		("TEER", "integritee"),
		("KSM", "kusama"),
		("BTC", "bitcoin"),
	]);
}

/// CoinGecko oracle source.
#[derive(Default)]
pub struct CoinGeckoSource;

impl CoinGeckoSource {
	fn map_crypto_currency_id(trading_pair: &TradingPair) -> Result<String, Error> {
		let key = &trading_pair.crypto_currency;
		match SYMBOL_ID_MAP.get(key.as_str()) {
			Some(v) => Ok(v.to_string()),
			None => Err(Error::InvalidCryptoCurrencyId),
		}
	}
}

impl<OracleSourceInfo: Into<TradingInfo>> OracleSource<OracleSourceInfo> for CoinGeckoSource {
	type OracleRequestResult = Result<(), Error>;

	fn metrics_id(&self) -> String {
		"coin_gecko".to_string()
	}

	fn request_timeout(&self) -> Option<Duration> {
		Some(COINGECKO_TIMEOUT)
	}

	fn base_url(&self) -> Result<Url, Error> {
		Url::parse(COINGECKO_URL).map_err(|e| Error::Other(format!("{:?}", e).into()))
	}

	fn root_certificate_content(&self) -> String {
		COINGECKO_ROOT_CERTIFICATE.to_string()
	}

	fn execute_request(
		_rest_client: &mut RestClient<HttpClient<SendWithCertificateVerification>>,
		source_info: OracleSourceInfo,
	) -> Self::OracleRequestResult {
		let _trading_info: TradingInfo = source_info.into();
		// TODO Implement me
		Ok(())
	}

	fn execute_exchange_rate_request(
		&self,
		rest_client: &mut RestClient<HttpClient<SendWithCertificateVerification>>,
		trading_pair: TradingPair,
	) -> Result<ExchangeRate, Error> {
		let fiat_id = trading_pair.fiat_currency.clone();
		let crypto_id = Self::map_crypto_currency_id(&trading_pair)?;

		let response = rest_client.get_with::<String, CoinGeckoMarket>(
			COINGECKO_PATH.to_string(),
			&[(COINGECKO_PARAM_CURRENCY, &fiat_id), (COINGECKO_PARAM_COIN, &crypto_id)],
		);

		let response = match response {
			Ok(response) => response,
			Err(e) => {
				error!("coingecko execute_exchange_rate_request() failed with: {:#?}", &e);
				return Err(Error::RestClient(e))
			},
		};

		debug!("coingecko received response: {:#?}", &response);
		let list = response.0;
		if list.is_empty() {
			return Err(Error::NoValidData(COINGECKO_URL.to_string(), trading_pair.key()))
		}

		match list[0].current_price {
			Some(r) => Ok(ExchangeRate::from_num(r)),
			None => Err(Error::EmptyExchangeRate(trading_pair)),
		}
	}
}

#[derive(Serialize, Deserialize, Debug)]
struct CoinGeckoMarketStruct {
	id: String,
	symbol: String,
	name: String,
	current_price: Option<f32>,
	last_updated: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct CoinGeckoMarket(pub Vec<CoinGeckoMarketStruct>);

impl RestPath<String> for CoinGeckoMarket {
	fn get_path(path: String) -> Result<String, itc_rest_client::error::Error> {
		Ok(path)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::MetricsExporterMock,
		oracles::exchange_rate_oracle::{ExchangeRateOracle, GetExchangeRate},
	};
	use core::assert_matches::assert_matches;
	use std::sync::Arc;

	type TestCoinGeckoClient = ExchangeRateOracle<CoinGeckoSource, MetricsExporterMock>;

	fn get_coin_gecko_crypto_currency_id(crypto_currency: &str) -> Result<String, Error> {
		let trading_pair = TradingPair {
			crypto_currency: crypto_currency.to_string(),
			fiat_currency: "USD".to_string(),
		};
		CoinGeckoSource::map_crypto_currency_id(&trading_pair)
	}

	#[test]
	fn crypto_currency_id_works_for_dot() {
		let coin_id = get_coin_gecko_crypto_currency_id("DOT").unwrap();
		assert_eq!(&coin_id, "polkadot");
	}

	#[test]
	fn crypto_currency_id_works_for_teer() {
		let coin_id = get_coin_gecko_crypto_currency_id("TEER").unwrap();
		assert_eq!(&coin_id, "integritee");
	}

	#[test]
	fn crypto_currency_id_works_for_ksm() {
		let coin_id = get_coin_gecko_crypto_currency_id("KSM").unwrap();
		assert_eq!(&coin_id, "kusama");
	}

	#[test]
	fn crypto_currency_id_works_for_btc() {
		let coin_id = get_coin_gecko_crypto_currency_id("BTC").unwrap();
		assert_eq!(&coin_id, "bitcoin");
	}

	#[test]
	fn crypto_currency_id_fails_for_undefined_crypto_currency() {
		let result = get_coin_gecko_crypto_currency_id("Undefined");
		assert_matches!(result, Err(Error::InvalidCryptoCurrencyId));
	}

	#[test]
	fn get_exchange_rate_for_undefined_fiat_currency_fails() {
		let coin_gecko_client = create_coin_gecko_client();
		let trading_pair =
			TradingPair { crypto_currency: "DOT".to_string(), fiat_currency: "CH".to_string() };
		let result = coin_gecko_client.get_exchange_rate(trading_pair);
		assert_matches!(result, Err(Error::RestClient(_)));
	}

	fn create_coin_gecko_client() -> TestCoinGeckoClient {
		TestCoinGeckoClient::new(CoinGeckoSource {}, Arc::new(MetricsExporterMock::default()))
	}
}
