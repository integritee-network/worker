use derive_more::{Display, From};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display, From)]
pub enum Error {
	Codec(codec::Error),
	Onchain(itp_storage_verifier::Error),
	Other(&'static str),
}
