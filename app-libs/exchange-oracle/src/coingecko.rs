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

use crate::{error::Error, GetExchangeRate};
use itc_rest_client::{http_client::HttpClient, rest_client::RestClient, RestGet, RestPath};
use log::*;
use serde::{Deserialize, Serialize};
use std::{
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
	fn get_exchange_rate(&mut self, coin: &str, currency: &str) -> Result<f32, Error> {
		let response = self
			.client
			.get_with::<String, CoinGeckoMarket>(
				COINGECKO_PATH.to_string(),
				&[(COINGECKO_PARAM_CURRENCY, currency), (COINGECKO_PARAM_COIN, coin)],
			)
			.map_err(Error::RestClient)?;
		let list = response.0;
		if list.is_empty() {
			error!("Got no market data from coinGecko. Check params {},{}", currency, coin);
			return Err(Error::NoValidData)
		}
		match list[0].current_price {
			Some(r) => Ok(r),
			None => {
				error!("Failed to get the exchange rate of {} to {}", currency, coin);
				Err(Error::EmptyExchangeRate)
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use core::assert_matches::assert_matches;

	#[test]
	fn get_exchange_rate_for_undefined_coins_fails() {
		let url = CoinGeckoClient::base_url().unwrap();
		let mut coingecko_client = CoinGeckoClient::new(url);
		let result = coingecko_client.get_exchange_rate("invalid_coin", "usd");
		assert_matches!(result, Err(Error::NoValidData));
	}

	#[test]
	fn get_exchange_rate_for_undefined_currency_fails() {
		let url = CoinGeckoClient::base_url().unwrap();
		let mut coingecko_client = CoinGeckoClient::new(url);
		let result = coingecko_client.get_exchange_rate("polkadot", "ch");
		assert_matches!(result, Err(Error::RestClient(_)));
	}

	#[test]
	fn get_exchange_rate_from_coingecko_works() {
		let url = CoinGeckoClient::base_url().unwrap();
		let mut coingecko_client = CoinGeckoClient::new(url);
		let dot_usd = coingecko_client.get_exchange_rate("polkadot", "usd").unwrap();
		assert!(dot_usd > 0f32);
		let bit_usd = coingecko_client.get_exchange_rate("bitcoin", "usd").unwrap();
		assert!(bit_usd > 0f32);
		let dot_chf = coingecko_client.get_exchange_rate("polkadot", "chf").unwrap();
		assert!(dot_chf > 0f32);
		let bit_chf = coingecko_client.get_exchange_rate("bitcoin", "chf").unwrap();
		assert!(bit_chf > 0f32);
		assert_eq!(
			(dot_usd * 100000. / bit_usd).round() / 100000.,
			(dot_chf * 100000. / bit_chf).round() / 100000.
		);
	}
}
