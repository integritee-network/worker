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

use crate::{metrics_exporter::ExportMetrics, traits::OracleSource, types::WeatherInfo, Error};
use itc_rest_client::{
	http_client::{HttpClient, SendWithCertificateVerification},
	rest_client::RestClient,
};
use log::*;
use std::sync::Arc;
use url::Url;

#[allow(unused)]
pub struct WeatherOracle<OracleSourceType, MetricsExporter> {
	oracle_source: OracleSourceType,
	metrics_exporter: Arc<MetricsExporter>,
}

impl<OracleSourceType, MetricsExporter> WeatherOracle<OracleSourceType, MetricsExporter>
where
	OracleSourceType: OracleSource<WeatherInfo>,
{
	pub fn new(oracle_source: OracleSourceType, metrics_exporter: Arc<MetricsExporter>) -> Self {
		WeatherOracle { oracle_source, metrics_exporter }
	}

	pub fn get_base_url(&self) -> Result<Url, Error> {
		self.oracle_source.base_url()
	}
}

pub trait GetLongitude {
	type LongitudeResult;
	fn get_longitude(&self, weather_info: WeatherInfo) -> Self::LongitudeResult;
}

impl<OracleSourceType, MetricsExporter> GetLongitude
	for WeatherOracle<OracleSourceType, MetricsExporter>
where
	OracleSourceType: OracleSource<WeatherInfo, OracleRequestResult = Result<f32, Error>>,
	MetricsExporter: ExportMetrics<WeatherInfo>,
{
	type LongitudeResult = Result<f32, Error>;

	fn get_longitude(&self, weather_info: WeatherInfo) -> Self::LongitudeResult {
		let query = weather_info.weather_query.clone();

		let base_url = self.oracle_source.base_url()?;
		let root_certificate = self.oracle_source.root_certificate_content();

		debug!("Get longitude from URI: {}, query: {:?}", base_url, query);

		let http_client = HttpClient::new(
			SendWithCertificateVerification::new(root_certificate),
			true,
			self.oracle_source.request_timeout(),
			None,
			None,
		);
		let mut rest_client = RestClient::new(http_client, base_url);
		<OracleSourceType as OracleSource<WeatherInfo>>::execute_request(
			&mut rest_client,
			weather_info,
		)
	}
}
