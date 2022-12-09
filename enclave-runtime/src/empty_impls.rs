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

/// Empty tests entry for production mode.
#[cfg(not(feature = "test"))]
#[no_mangle]
pub extern "C" fn test_main_entrance() -> sgx_types::size_t {
	unreachable!("Tests are not available when compiled in production mode.")
}

/// Empty Teeracle market data implementation.
#[cfg(not(feature = "teeracle"))]
#[no_mangle]
pub unsafe extern "C" fn update_market_data_xt(
	_crypto_currency_ptr: *const u8,
	_crypto_currency_size: u32,
	_fiat_currency_ptr: *const u8,
	_fiat_currency_size: u32,
	_unchecked_extrinsic: *mut u8,
	_unchecked_extrinsic_size: u32,
) -> sgx_types::sgx_status_t {
	unreachable!("Cannot update market data, teeracle feature is not enabled.")
}

/// Empty Teeracle Weather data implementation.
#[cfg(not(feature = "teeracle"))]
#[no_mangle]
pub unsafe extern "C" fn update_weather_data_xt(
	_weather_info_longitude: *const u8,
	_weather_info_longitude_size: u32,
	_weather_info_latitude: *const u8,
	_weather_info_latitude_size: u32,
	_unchecked_extrinsic: *mut u8,
	_unchecked_extrinsic_size: u32,
) -> sgx_types::sgx_status_t {
	unreachable!("Cannot update weather data, teeracle feature is not enabled.")
}
