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

//! Integration tests for concrete exchange rate oracle implementations.
//! Uses real HTTP requests, so the sites must be available for these tests.

use crate::{
	error::Error,
	mock::MetricsExporterMock,
	oracle_sources::{
		coin_gecko::CoinGeckoSource, coin_market_cap::CoinMarketCapSource,
		weather_oracle_source::WeatherOracleSource,
	},
	oracles::{
		exchange_rate_oracle::{ExchangeRateOracle, GetExchangeRate},
		weather_oracle::{GetLongitude, WeatherOracle},
	},
	traits::OracleSource,
	types::{TradingInfo, TradingPair, WeatherInfo, WeatherQuery},
};
use core::assert_matches::assert_matches;
use std::sync::Arc;
use substrate_fixed::transcendental::ZERO;

type TestOracle<OracleSource> = ExchangeRateOracle<OracleSource, MetricsExporterMock>;
type TestWeatherOracle<OracleSource> = WeatherOracle<OracleSource, MetricsExporterMock>;

#[test]
#[ignore = "requires API key for CoinMarketCap"]
fn get_exchange_rate_from_coin_market_cap_works() {
	test_suite_exchange_rates::<CoinMarketCapSource>();
}

#[test]
#[ignore = "requires external coin gecko service, disabled temporarily"]
fn get_exchange_rate_from_coin_gecko_works() {
	test_suite_exchange_rates::<CoinGeckoSource>();
}

#[test]
fn get_longitude_from_open_meteo_works() {
	let oracle = create_weather_oracle::<WeatherOracleSource>();
	let weather_query =
		WeatherQuery { latitude: "52.52".into(), longitude: "13.41".into(), hourly: "none".into() };
	// Todo: hourly param is temperature_2m to get temp or relativehumidity_2m to get humidity
	let weather_info = WeatherInfo { weather_query };
	let expected_longitude = 13.41f32;
	let response_longitude =
		oracle.get_longitude(weather_info).expect("Can grab longitude from oracle");
	assert!((response_longitude - expected_longitude) < 0.5);
}

#[test]
fn get_exchange_rate_for_undefined_coin_market_cap_crypto_currency_fails() {
	get_exchange_rate_for_undefined_crypto_currency_fails::<CoinMarketCapSource>();
}

#[test]
fn get_exchange_rate_for_undefined_coin_gecko_crypto_currency_fails() {
	get_exchange_rate_for_undefined_crypto_currency_fails::<CoinGeckoSource>();
}

fn create_weather_oracle<OracleSourceType: OracleSource<WeatherInfo>>(
) -> TestWeatherOracle<OracleSourceType> {
	let oracle_source = OracleSourceType::default();
	WeatherOracle::new(oracle_source, Arc::new(MetricsExporterMock::default()))
}

fn create_exchange_rate_oracle<OracleSourceType: OracleSource<TradingInfo>>(
) -> TestOracle<OracleSourceType> {
	let oracle_source = OracleSourceType::default();
	ExchangeRateOracle::new(oracle_source, Arc::new(MetricsExporterMock::default()))
}

fn get_exchange_rate_for_undefined_crypto_currency_fails<
	OracleSourceType: OracleSource<TradingInfo>,
>() {
	let oracle = create_exchange_rate_oracle::<OracleSourceType>();
	let trading_pair = TradingPair {
		crypto_currency: "invalid_coin".to_string(),
		fiat_currency: "USD".to_string(),
	};
	let result = oracle.get_exchange_rate(trading_pair);
	assert_matches!(result, Err(Error::InvalidCryptoCurrencyId));
}

fn test_suite_exchange_rates<OracleSourceType: OracleSource<TradingInfo>>() {
	let oracle = create_exchange_rate_oracle::<OracleSourceType>();
	let dot_to_usd =
		TradingPair { crypto_currency: "DOT".to_string(), fiat_currency: "USD".to_string() };
	let dot_usd = oracle.get_exchange_rate(dot_to_usd).unwrap().0;
	assert!(dot_usd > 0f32);
	let btc_to_usd =
		TradingPair { crypto_currency: "BTC".to_string(), fiat_currency: "USD".to_string() };
	let bit_usd = oracle.get_exchange_rate(btc_to_usd).unwrap().0;
	assert!(bit_usd > 0f32);
	let dot_to_chf =
		TradingPair { crypto_currency: "DOT".to_string(), fiat_currency: "CHF".to_string() };
	let dot_chf = oracle.get_exchange_rate(dot_to_chf).unwrap().0;
	assert!(dot_chf > 0f32);
	let bit_to_chf =
		TradingPair { crypto_currency: "BTC".to_string(), fiat_currency: "CHF".to_string() };
	let bit_chf = oracle.get_exchange_rate(bit_to_chf).unwrap().0;

	// Ensure that get_exchange_rate returns a positive rate
	assert!(dot_usd > ZERO);

	// Ensure that get_exchange_rate returns a valid value by checking
	// that the values obtained for DOT/BIT from different exchange rates are the same
	assert_eq!((dot_usd / bit_usd).round(), (dot_chf / bit_chf).round());
}
