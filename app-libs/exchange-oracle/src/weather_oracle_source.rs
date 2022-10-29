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
	types::{ExchangeRate, TradingPair, TradingInfo, WeatherInfo, WeatherQuery},
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


const WEATHER_URL: &str = "https://api.open-meteo.com";
const WEATHER_PARAM_LONGITUDE: &str = "longitude";
const WEATHER_PARAM_LATITUDE: &str = "latitude";
const WEATHER_PARAM_HOURLY: &str = "hourly";
const WEATHER_PATH: &str = "v1/forecast";
const WEATHER_TIMEOUT: Duration = Duration::from_secs(3u64);
const WEATHER_ROOT_CERTIFICATE: &str =
	include_str!("certificates/open_meteo_root.pem");

#[derive(Default)]
pub struct WeatherOracleSource;

impl OracleSource for WeatherOracleSource {
    type OracleRequestResult = Result<f32, Error>; //TODO: Need to return some Data
	type OracleSourceInfo = WeatherInfo;

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
		source_info: Self::OracleSourceInfo
	) -> Self::OracleRequestResult {
		let query = source_info.weather_query;

		let response = rest_client
			.get_with::<String, OpenMeteo>(
				WEATHER_PATH.into(),
				&[
					(WEATHER_PARAM_LATITUDE, &query.latitude),
					(WEATHER_PARAM_LONGITUDE, &query.longtitude),
				],
			)
			.map_err(Error::RestClient)?;

		let open_meteo_weather_struct = response.0;

        Ok(open_meteo_weather_struct.longitude)
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct OpenMeteoWeatherStruct {
	latitude: f32,
	longitude: f32,
}

#[derive(Serialize, Deserialize, Debug)]
struct OpenMeteo(pub OpenMeteoWeatherStruct);

impl RestPath<String> for OpenMeteo {
	fn get_path(path: String) -> Result<String, itc_rest_client::error::Error> {
		Ok(path)
	}
}
