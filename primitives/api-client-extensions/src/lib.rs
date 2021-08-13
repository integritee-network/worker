//! Some substrate-api-client extension traits.

use substrate_api_client::ApiClientError;

pub mod account;
pub mod chain;
pub mod pallet_teerex;

pub use account::*;
pub use chain::*;
pub use pallet_teerex::*;

pub type ApiResult<T> = Result<T, ApiClientError>;
