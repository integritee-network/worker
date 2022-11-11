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

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

use codec::{Decode, Encode};
use std::string::String;
use substrate_fixed::types::U32F32;

// FIXME: Copied from ita-oracle because of cyclic deps. Should be removed after integritee-network/pallets#71
pub type ExchangeRate = U32F32;

#[derive(Encode, Decode, Debug)]
pub enum EnclaveMetric {
	SetSidechainBlockHeight(u64),
	TopPoolSizeSet(u64),
	TopPoolSizeIncrement,
	TopPoolSizeDecrement,
	ExchangeRateOracle(ExchangeRateOracleMetric),
	// OracleMetric(OracleMetric<MetricsInfo>),
}

#[derive(Encode, Decode, Debug)]
pub enum ExchangeRateOracleMetric {
	/// Exchange Rate from CoinGecko - (Source, TradingPair, ExchangeRate)
	ExchangeRate(String, String, ExchangeRate),
	/// Response time of the request in [ms]. (Source, ResponseTime)
	ResponseTime(String, u128),
	/// Increment the number of requests (Source)
	NumberRequestsIncrement(String),
}

#[derive(Encode, Decode, Debug)]
pub enum OracleMetric<MetricsInfo> {
	OracleSpecificMetric(MetricsInfo),
	ResponseTime(String, u128),
	NumberRequestsIncrement(String),
}
