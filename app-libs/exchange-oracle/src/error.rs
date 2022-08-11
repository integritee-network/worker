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

use crate::types::TradingPair;
use std::{boxed::Box, string::String};

/// Exchange rate error
#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("Rest client error")]
	RestClient(#[from] itc_rest_client::error::Error),
	#[error("Could not retrieve any data from {0} for {1}")]
	NoValidData(String, String),
	#[error("Value for exchange rate is null")]
	EmptyExchangeRate(TradingPair),
	#[error("Invalid id for crypto currency")]
	InvalidCryptoCurrencyId,
	#[error("Invalid id for fiat currency")]
	InvalidFiatCurrencyId,
	#[error(transparent)]
	Other(#[from] Box<dyn std::error::Error + Sync + Send + 'static>),
}
