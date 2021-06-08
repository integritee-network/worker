//! Some substrate-api-client extension traits.

use substrate_api_client::ApiClientError;

pub mod account;
pub mod substratee_registry;
pub mod chain;

pub use account::*;
pub use substratee_registry::*;
pub use chain::*;

pub type ApiResult<T> = Result<T, ApiClientError>;
