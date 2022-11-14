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
	types::{ExchangeRate, TradingPair},
	Error,
};
use core::time::Duration;
use itc_rest_client::{
	http_client::{HttpClient, SendWithCertificateVerification},
	rest_client::RestClient,
};
use std::string::String;
use url::Url;

pub trait OracleSource<OracleSourceInfo>: Default {
	type OracleRequestResult;

	fn metrics_id(&self) -> String;

	fn request_timeout(&self) -> Option<Duration>;

	fn base_url(&self) -> Result<Url, Error>;

	/// The server's root certificate. A valid certificate is required to open a tls connection
	fn root_certificate_content(&self) -> String;

	fn execute_exchange_rate_request(
		&self,
		rest_client: &mut RestClient<HttpClient<SendWithCertificateVerification>>,
		trading_pair: TradingPair,
	) -> Result<ExchangeRate, Error>;

	fn execute_request(
		rest_client: &mut RestClient<HttpClient<SendWithCertificateVerification>>,
		source_info: OracleSourceInfo,
	) -> Self::OracleRequestResult;
}
