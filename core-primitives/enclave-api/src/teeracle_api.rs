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

use crate::{error::Error, Enclave, EnclaveResult};
use codec::Encode;
use frame_support::ensure;
use itp_enclave_api_ffi as ffi;
use log::*;
use sgx_types::*;

pub trait TeeracleApi: Send + Sync + 'static {
	/// Update the currency market data for the token oracle.
	fn update_market_data_xt(
		&self,
		crypto_currency: &str,
		fiat_currency: &str,
	) -> EnclaveResult<Vec<u8>>;

	/// Update weather data for the corresponding coordinates.
	fn update_weather_data_xt(&self, longitude: &str, latitude: &str) -> EnclaveResult<Vec<u8>>;
}

impl TeeracleApi for Enclave {
	fn update_market_data_xt(
		&self,
		crypto_currency: &str,
		fiat_currency: &str,
	) -> EnclaveResult<Vec<u8>> {
		info!(
			"TeeracleApi update_market_data_xt in with crypto {} and fiat {}",
			crypto_currency, fiat_currency
		);
		let mut retval = sgx_status_t::SGX_SUCCESS;
		let response_len = 8192;
		let mut response: Vec<u8> = vec![0u8; response_len as usize];

		let crypto_curr = crypto_currency.encode();
		let fiat_curr = fiat_currency.encode();

		let res = unsafe {
			ffi::update_market_data_xt(
				self.eid,
				&mut retval,
				crypto_curr.as_ptr(),
				crypto_curr.len() as u32,
				fiat_curr.as_ptr(),
				fiat_curr.len() as u32,
				response.as_mut_ptr(),
				response_len,
			)
		};

		ensure!(res == sgx_status_t::SGX_SUCCESS, Error::Sgx(res));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(response)
	}
	fn update_weather_data_xt(&self, longitude: &str, latitude: &str) -> EnclaveResult<Vec<u8>> {
		info!(
			"TeeracleApi update_weather_data_xt in with latitude: {}, longitude: {}",
			latitude, longitude
		);
		let mut retval = sgx_status_t::SGX_SUCCESS;
		let response_len = 8192;
		let mut response: Vec<u8> = vec![0u8; response_len as usize];

		let longitude_encoded: Vec<u8> = longitude.encode();
		let latitude_encoded: Vec<u8> = latitude.encode();

		let res = unsafe {
			ffi::update_weather_data_xt(
				self.eid,
				&mut retval,
				longitude_encoded.as_ptr(),
				longitude_encoded.len() as u32,
				latitude_encoded.as_ptr(),
				latitude_encoded.len() as u32,
				response.as_mut_ptr(),
				response_len,
			)
		};

		ensure!(res == sgx_status_t::SGX_SUCCESS, Error::Sgx(res));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));
		Ok(response)
	}
}
