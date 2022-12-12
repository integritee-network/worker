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
use serde::{Deserialize, Serialize};
use std::{
	collections::{BTreeMap, HashMap},
	env,
	string::{String, ToString},
	time::Duration,
};
use url::Url;

const COINMARKETCAP_URL: &str = "https://pro-api.coinmarketcap.com";
const COINMARKETCAP_KEY_PARAM: &str = "CMC_PRO_API_KEY";
const FIAT_CURRENCY_PARAM: &str = "convert_id";
const CRYPTO_CURRENCY_PARAM: &str = "id";
const COINMARKETCAP_PATH: &str = "v2/cryptocurrency/quotes/latest"; // API endpoint to get the exchange rate with a basic API plan (free)
const COINMARKETCAP_TIMEOUT: Duration = Duration::from_secs(3u64);
const COINMARKETCAP_ROOT_CERTIFICATE: &str = include_str!("../certificates/amazon_root_ca_a.pem");

lazy_static! {
	static ref CRYPTO_SYMBOL_ID_MAP: HashMap<&'static str, &'static str> =
		HashMap::from([("DOT", "6636"), ("TEER", "13323"), ("KSM", "5034"), ("BTC", "1"),]);
	static ref COINMARKETCAP_KEY: String = env::var("COINMARKETCAP_KEY").unwrap_or_default();
}

lazy_static! {
	static ref FIAT_SYMBOL_ID_MAP: HashMap<&'static str, &'static str> =
		HashMap::from([("USD", "2781"), ("EUR", "2790"), ("CHF", "2785"), ("JPY", "2797"),]);
}

#[derive(Default)]
pub struct CoinMarketCapSource;

impl CoinMarketCapSource {
	fn map_crypto_currency_id(trading_pair: &TradingPair) -> Result<String, Error> {
		CRYPTO_SYMBOL_ID_MAP
			.get(trading_pair.crypto_currency.as_str())
			.map(|v| v.to_string())
			.ok_or(Error::InvalidCryptoCurrencyId)
	}

	fn map_fiat_currency_id(trading_pair: &TradingPair) -> Result<String, Error> {
		FIAT_SYMBOL_ID_MAP
			.get(trading_pair.fiat_currency.as_str())
			.map(|v| v.to_string())
			.ok_or(Error::InvalidFiatCurrencyId)
	}
}

impl<OracleSourceInfo: Into<TradingInfo>> OracleSource<OracleSourceInfo> for CoinMarketCapSource {
	// TODO Change this to return something useful?
	type OracleRequestResult = Result<(), Error>;

	fn metrics_id(&self) -> String {
		"coin_market_cap".to_string()
	}

	fn request_timeout(&self) -> Option<Duration> {
		Some(COINMARKETCAP_TIMEOUT)
	}

	fn base_url(&self) -> Result<Url, Error> {
		Url::parse(COINMARKETCAP_URL).map_err(|e| Error::Other(format!("{:?}", e).into()))
	}

	fn root_certificate_content(&self) -> String {
		COINMARKETCAP_ROOT_CERTIFICATE.to_string()
	}

	fn execute_request(
		_rest_client: &mut RestClient<HttpClient<SendWithCertificateVerification>>,
		source_info: OracleSourceInfo,
	) -> Self::OracleRequestResult {
		let trading_info: TradingInfo = source_info.into();
		let _fiat_currency = trading_info.trading_pair.fiat_currency;
		let _crypto_currency = trading_info.trading_pair.crypto_currency;
		// TODO Implement me
		Ok(())
	}

	fn execute_exchange_rate_request(
		&self,
		rest_client: &mut RestClient<HttpClient<SendWithCertificateVerification>>,
		trading_pair: TradingPair,
	) -> Result<ExchangeRate, Error> {
		let fiat_id = Self::map_fiat_currency_id(&trading_pair)?;
		let crypto_id = Self::map_crypto_currency_id(&trading_pair)?;

		let response = rest_client
			.get_with::<String, CoinMarketCapMarket>(
				COINMARKETCAP_PATH.to_string(),
				&[
					(FIAT_CURRENCY_PARAM, &fiat_id),
					(CRYPTO_CURRENCY_PARAM, &crypto_id),
					(COINMARKETCAP_KEY_PARAM, &COINMARKETCAP_KEY),
				],
			)
			.map_err(Error::RestClient)?;

		let data_struct = response.0;

		let data = match data_struct.data.get(&crypto_id) {
			Some(d) => d,
			None =>
				return Err(Error::NoValidData(
					COINMARKETCAP_URL.to_string(),
					trading_pair.crypto_currency,
				)),
		};

		let quote = match data.quote.get(&fiat_id) {
			Some(q) => q,
			None =>
				return Err(Error::NoValidData(COINMARKETCAP_URL.to_string(), trading_pair.key())),
		};
		match quote.price {
			Some(r) => Ok(ExchangeRate::from_num(r)),
			None => Err(Error::EmptyExchangeRate(trading_pair)),
		}
	}
}

#[derive(Serialize, Deserialize, Debug)]
struct DataStruct {
	id: Option<u32>,
	name: String,
	symbol: String,
	quote: BTreeMap<String, QuoteStruct>,
}

#[derive(Serialize, Deserialize, Debug)]
struct QuoteStruct {
	price: Option<f32>,
	last_updated: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct CoinMarketCapMarketStruct {
	data: BTreeMap<String, DataStruct>,
}

#[derive(Serialize, Deserialize, Debug)]
struct CoinMarketCapMarket(pub CoinMarketCapMarketStruct);

impl RestPath<String> for CoinMarketCapMarket {
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

	type TestClient = ExchangeRateOracle<CoinMarketCapSource, MetricsExporterMock>;

	fn get_coin_market_cap_crypto_currency_id(crypto_currency: &str) -> Result<String, Error> {
		let trading_pair = TradingPair {
			crypto_currency: crypto_currency.to_string(),
			fiat_currency: "USD".to_string(),
		};
		CoinMarketCapSource::map_crypto_currency_id(&trading_pair)
	}

	#[test]
	fn crypto_currency_id_works_for_dot() {
		let coin_id = get_coin_market_cap_crypto_currency_id("DOT").unwrap();
		assert_eq!(&coin_id, "6636");
	}

	#[test]
	fn crypto_currency_id_works_for_teer() {
		let coin_id = get_coin_market_cap_crypto_currency_id("TEER").unwrap();
		assert_eq!(&coin_id, "13323");
	}

	#[test]
	fn crypto_currency_id_works_for_ksm() {
		let coin_id = get_coin_market_cap_crypto_currency_id("KSM").unwrap();
		assert_eq!(&coin_id, "5034");
	}

	#[test]
	fn crypto_currency_id_works_for_btc() {
		let coin_id = get_coin_market_cap_crypto_currency_id("BTC").unwrap();
		assert_eq!(&coin_id, "1");
	}

	#[test]
	fn crypto_currency_id_fails_for_undefined_crypto_currency() {
		let coin_id = get_coin_market_cap_crypto_currency_id("Undefined");
		assert_matches!(coin_id, Err(Error::InvalidCryptoCurrencyId));
	}

	#[test]
	fn get_exchange_rate_for_undefined_fiat_currency_fails() {
		let coin_market_cap_client = create_client();
		let trading_pair =
			TradingPair { crypto_currency: "DOT".to_string(), fiat_currency: "CH".to_string() };
		let result = coin_market_cap_client.get_exchange_rate(trading_pair);
		assert_matches!(result, Err(Error::InvalidFiatCurrencyId));
	}

	fn create_client() -> TestClient {
		TestClient::new(CoinMarketCapSource {}, Arc::new(MetricsExporterMock::default()))
	}
}
