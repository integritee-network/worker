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
use std::boxed::Box;

/// Exchange rate error
#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("Rest client error")]
	RestClient(itc_rest_client::error::Error),
	#[error("Other error")]
	Other(Box<dyn std::error::Error>),
	#[error("Could not retrieve any data")]
	NoValidData,
	#[error("Value for exchange rate is null")]
	EmptyExchangeRate,
	#[error("Invalid id for crypto currency")]
	InvalidCryptoCurrencyId,
}
