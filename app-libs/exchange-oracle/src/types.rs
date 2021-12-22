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
extern crate sgx_tstd as std;

use crate::error::Error;
use codec::{Decode, Encode};
use std::string::String;

/// Market identifier for order
#[derive(Debug, Clone, Encode, Decode)]
pub struct TradingPair {
	pub crypto_currency: String,
	pub fiat_currency: String,
}

impl TradingPair {
	pub fn key(self) -> String {
		format!("{}/{}", self.crypto_currency, self.fiat_currency)
	}
}

pub trait TradingPairId {
	fn crypto_currency_id(&mut self, trading_pair: TradingPair) -> Result<String, Error> {
		Ok(trading_pair.crypto_currency)
	}

	fn fiat_currency_id(&mut self, trading_pair: TradingPair) -> Result<String, Error> {
		Ok(trading_pair.fiat_currency)
	}
}
