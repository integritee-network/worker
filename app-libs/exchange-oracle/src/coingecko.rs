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
	types::{TradingPair, TradingPairId},
	ExchangeRate, GetExchangeRate,
};
use itc_rest_client::{http_client::HttpClient, rest_client::RestClient, RestGet, RestPath};
use lazy_static::lazy_static;
use log::*;
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
const COINGECKO_TIMEOUT: Duration = Duration::from_secs(3u64);

//TODO: Get coingecko coins' id from coingecko API ? For now add here the mapping symbol to id
lazy_static! {
	static ref SYMBOL_ID_MAP: HashMap<&'static str, &'static str> = HashMap::from([
		("DOT", "polkadot"),
		("TEER", "integritee"),
		("KSM", "kusama"),
		("BTC", "bitcoin"),
	]);
}
/// REST client to make requests to CoinGecko.
pub struct CoinGeckoClient {
	client: RestClient<HttpClient>,
}
impl CoinGeckoClient {
	pub fn new(baseurl: Url) -> Self {
		let http_client = HttpClient::new(true, Some(COINGECKO_TIMEOUT), None, None);
		let rest_client = RestClient::new(http_client, baseurl);
		CoinGeckoClient { client: rest_client }
	}
	pub fn base_url() -> Result<Url, Error> {
		Url::parse(COINGECKO_URL).map_err(|e| Error::Other(format!("{:?}", e).into()))
	}
}

impl TradingPairId for CoinGeckoClient {
	fn crypto_currency_id(&mut self, trading_pair: TradingPair) -> Result<String, Error> {
		let key = trading_pair.crypto_currency;
		match SYMBOL_ID_MAP.get(&key as &str) {
			Some(v) => Ok(v.to_string()),
			None => Err(Error::InvalidCryptoCurrencyId),
		}
	}
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CoinGeckoMarketStruct {
	id: String,
	symbol: String,
	name: String,
	current_price: Option<f32>,
	last_updated: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CoinGeckoMarket(pub Vec<CoinGeckoMarketStruct>);

impl RestPath<String> for CoinGeckoMarket {
	fn get_path(path: String) -> Result<String, itc_rest_client::error::Error> {
		Ok(path)
	}
}

impl GetExchangeRate for CoinGeckoClient {
	fn get_exchange_rate(&mut self, trading_pair: TradingPair) -> Result<ExchangeRate, Error> {
		let fiat_id = self.fiat_currency_id(trading_pair.clone())?;
		let crypto_id = self.crypto_currency_id(trading_pair.clone())?;
		let response = self
			.client
			.get_with::<String, CoinGeckoMarket>(
				COINGECKO_PATH.to_string(),
				&[(COINGECKO_PARAM_CURRENCY, &fiat_id), (COINGECKO_PARAM_COIN, &crypto_id)],
			)
			.map_err(Error::RestClient)?;
		let list = response.0;
		if list.is_empty() {
			error!("Got no market data from coinGecko. Check params {:?} ", trading_pair);
			return Err(Error::NoValidData)
		}
		match list[0].current_price {
			Some(r) => Ok(ExchangeRate::from_num(r)),
			None => {
				error!("Failed to get the exchange rate {}", TradingPair::key(trading_pair));
				Err(Error::EmptyExchangeRate)
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use core::assert_matches::assert_matches;

	fn get_coingecko_crypto_currency_id(crypto_currency: &str) -> Result<String, Error> {
		let url = CoinGeckoClient::base_url().unwrap();
		let mut coingecko_client = CoinGeckoClient::new(url);
		let trading_pair = TradingPair {
			crypto_currency: crypto_currency.to_string(),
			fiat_currency: "USD".to_string(),
		};
		coingecko_client.crypto_currency_id(trading_pair)
	}

	#[test]
	fn crypto_currency_id_works_for_dot() {
		let coin_id = get_coingecko_crypto_currency_id("DOT").unwrap();
		assert_eq!(&coin_id, "polkadot");
	}

	#[test]
	fn crypto_currency_id_works_for_teer() {
		let coin_id = get_coingecko_crypto_currency_id("TEER").unwrap();
		assert_eq!(&coin_id, "integritee");
	}

	#[test]
	fn crypto_currency_id_works_for_ksm() {
		let coin_id = get_coingecko_crypto_currency_id("KSM").unwrap();
		assert_eq!(&coin_id, "kusama");
	}

	#[test]
	fn crypto_currency_id_works_for_btc() {
		let coin_id = get_coingecko_crypto_currency_id("BTC").unwrap();
		assert_eq!(&coin_id, "bitcoin");
	}

	#[test]
	fn crypto_currency_id_fails_for_undefined_crypto_currency() {
		let result = get_coingecko_crypto_currency_id("Undefined");
		assert_matches!(result, Err(Error::InvalidCryptoCurrencyId));
	}

	#[test]
	fn get_exchange_rate_for_undefined_coingecko_crypto_currency_fails() {
		let url = CoinGeckoClient::base_url().unwrap();
		let mut coingecko_client = CoinGeckoClient::new(url);
		let trading_pair = TradingPair {
			crypto_currency: "invalid_coin".to_string(),
			fiat_currency: "USD".to_string(),
		};
		let result = coingecko_client.get_exchange_rate(trading_pair);
		assert_matches!(result, Err(Error::InvalidCryptoCurrencyId));
	}

	#[test]
	fn get_exchange_rate_for_undefined_fiat_currency_fails() {
		let url = CoinGeckoClient::base_url().unwrap();
		let mut coingecko_client = CoinGeckoClient::new(url);
		let trading_pair =
			TradingPair { crypto_currency: "DOT".to_string(), fiat_currency: "CH".to_string() };
		let result = coingecko_client.get_exchange_rate(trading_pair);
		assert_matches!(result, Err(Error::RestClient(_)));
	}

	#[test]
	fn get_exchange_rate_from_coingecko_works() {
		let url = CoinGeckoClient::base_url().unwrap();
		let mut coingecko_client = CoinGeckoClient::new(url);
		let dot_usd = coingecko_client
			.get_exchange_rate(TradingPair {
				crypto_currency: "DOT".to_string(),
				fiat_currency: "USD".to_string(),
			})
			.unwrap();
		let bit_usd = coingecko_client
			.get_exchange_rate(TradingPair {
				crypto_currency: "BTC".to_string(),
				fiat_currency: "USD".to_string(),
			})
			.unwrap();
		let dot_chf = coingecko_client
			.get_exchange_rate(TradingPair {
				crypto_currency: "DOT".to_string(),
				fiat_currency: "chf".to_string(),
			})
			.unwrap();
		let bit_chf = coingecko_client
			.get_exchange_rate(TradingPair {
				crypto_currency: "BTC".to_string(),
				fiat_currency: "chf".to_string(),
			})
			.unwrap();

		let zero = ExchangeRate::from_num(0);
		//Ensure that get_exchange_rate return a positive rate
		assert!(dot_usd > zero);
		//Ensure that the exchange rates' values make sense
		assert_eq!((dot_usd / bit_usd).round(), (dot_chf / bit_chf).round());
	}
}
