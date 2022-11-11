/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

use codec::alloc::string::ToString;
use ita_oracle::{
	create_coin_gecko_oracle, create_coin_market_cap_oracle,
	oracles::exchange_rate_oracle::GetExchangeRate, types::TradingPair,
};
use itp_test::mock::metrics_ocall_mock::MetricsOCallMock;
use std::sync::Arc;

pub(super) fn test_verify_get_exchange_rate_from_coin_gecko_works() {
	// Get the exchange rate
	let trading_pair =
		TradingPair { crypto_currency: "DOT".to_string(), fiat_currency: "USD".to_string() };

	let coin_gecko_oracle = create_coin_gecko_oracle(Arc::new(MetricsOCallMock::default()));

	let result = coin_gecko_oracle.get_exchange_rate(trading_pair.clone());
	assert!(result.is_ok());
}

/// Get exchange rate from coin market cap. Requires API key (therefore not suited for unit testing).
#[allow(unused)]
pub(super) fn test_verify_get_exchange_rate_from_coin_market_cap_works() {
	// Get the exchange rate
	let trading_pair =
		TradingPair { crypto_currency: "DOT".to_string(), fiat_currency: "USD".to_string() };

	let coin_market_cap_oracle =
		create_coin_market_cap_oracle(Arc::new(MetricsOCallMock::default()));

	let result = coin_market_cap_oracle.get_exchange_rate(trading_pair.clone());
	assert!(result.is_ok());
}
