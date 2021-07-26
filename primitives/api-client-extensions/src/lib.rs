//! Some substrate-api-client extension traits.

use substrate_api_client::ApiClientError;

pub mod account;
pub mod chain;
pub mod substratee_registry;

pub use account::*;
pub use chain::*;
pub use substratee_registry::*;

pub type ApiResult<T> = Result<T, ApiClientError>;
