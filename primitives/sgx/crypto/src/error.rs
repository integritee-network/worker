use derive_more::{Display, From};
use std::prelude::v1::Box;

#[derive(Debug, Display, From)]
pub enum Error {
	IO(std::io::Error),
	InvalidNonceKeyLength,
	Codec(codec::Error),
	Other(Box<dyn std::error::Error>),
}

pub type Result<T> = core::result::Result<T, Error>;
