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

use codec::{Decode, Encode};
use std::string::String;
use substrate_fixed::types::U32F32;

#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub struct WeatherInfo {
	pub weather_query: WeatherQuery,
}

#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub struct WeatherQuery {
	pub longitude: String,
	pub latitude: String,
	pub hourly: String,
}

impl WeatherQuery {
	pub fn key(self) -> String {
		format!("{}/{}", self.latitude, self.longitude)
	}
}

#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub struct TradingInfo {
	pub trading_pair: TradingPair,
	pub exchange_rate: ExchangeRate,
}
/// Market identifier for order
#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub struct TradingPair {
	pub crypto_currency: String,
	pub fiat_currency: String,
}

impl TradingPair {
	pub fn key(self) -> String {
		format!("{}/{}", self.crypto_currency, self.fiat_currency)
	}
}

/// TODO Fix https://github.com/integritee-network/pallets/issues/71 and get it from https://github.com/integritee-network/pallets.git
/// Teeracle types
pub type ExchangeRate = U32F32;
// pub type Coordinate = U32F32;
