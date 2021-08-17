use derive_more::{Display, From};

#[derive(Debug, Display, From)]
pub enum Error {
	IO(std::io::Error),
	InvalidNonceKeyLength,
	Codec(codec::Error),
}

pub type Result<T> = core::result::Result<T, Error>;
