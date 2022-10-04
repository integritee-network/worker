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

//! Some substrate-api-client extension traits.

pub use substrate_api_client::{rpc::WsRpcClient, Api, ApiClientError};

pub mod account;
pub mod chain;
pub mod pallet_teeracle;
pub mod pallet_teerex;
pub mod pallet_teerex_api_mock;

pub use account::*;
pub use chain::*;
pub use pallet_teeracle::*;
pub use pallet_teerex::*;

pub type ApiResult<T> = Result<T, ApiClientError>;
