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
	exchange_rate_oracle::OracleSource,
	types::{ExchangeRate, TradingPair},
};
use itc_rest_client::{
	http_client::{HttpClient, SendWithCertificateVerification},
	rest_client::RestClient,
	RestGet, RestPath,
};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{
	collections::HashMap,
	string::{String, ToString},
	time::Duration,
	vec::Vec,
};
use url::Url;


const WEATHER_URL: &str = " "; // URL of oracle source
const WEATHER_PARAM_TEMPERATURE: &str = " ";
const WEATHER_PARAM_HUMIDITY: &str = " ";
const WEATHER_PATH: &str = " ";
const WEATHER_TIMEOUT: Duration = Duration::from_secs(3u64);
const WEATHER_ROOT_CERTIFICATE: &str =
	include_str!("certificates/open_meteo_root.pem"); // Todo: Get certificate

#[derive(Default)]
pub struct WeatherOracleSource;

impl<OracleSourceInfo> OracleSource<OracleSourceInfo> for WeatherOracleSource {
    type OracleRequestResult = Result<(), Error>; //TODO: Need to return some Data

	fn metrics_id(&self) -> String {
        "weather".to_string() // TODO: Fix
    }

	fn request_timeout(&self) -> Option<Duration> {
        Some(WEATHER_TIMEOUT)
    }

	fn base_url(&self) -> Result<Url, Error> {
        Url::parse(WEATHER_URL).map_err(|e| Error::Other(format!("{:?}", e).into()))
    }

	/// The server's root certificate. A valid certificate is required to open a tls connection
	fn root_certificate_content(&self) -> String {
        WEATHER_ROOT_CERTIFICATE.to_string()
    }

	fn execute_exchange_rate_request(
		&self,
		rest_client: &mut RestClient<HttpClient<SendWithCertificateVerification>>,
		trading_pair: TradingPair,
	) -> Result<ExchangeRate, Error> {
        Err(Error::NoValidData("None".into(), "None".into()))
    }

	fn execute_request(
		&self,
		rest_client: &mut RestClient<HttpClient<SendWithCertificateVerification>>,
		source_info: OracleSourceInfo
	) -> Self::OracleRequestResult {
        Ok(())
    }
}