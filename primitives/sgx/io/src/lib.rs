#![cfg_attr(not(feature = "std"), no_std)]

//! SGX file IO abstractions

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

use std::{
	fs,
	io::{Read, Result as IOResult, Write},
	string::String,
	vec::Vec,
};

#[cfg(feature = "sgx")]
pub use sgx::*;

pub trait IO: Sized {
	type Error: From<std::io::Error>;

	fn read() -> Result<Self, Self::Error>;
	fn write(self) -> Result<(), Self::Error>;
}

pub trait SealIO: Sized {
	type Error: From<std::io::Error>;

	fn unseal() -> Result<Self, Self::Error>;
	fn seal(self) -> Result<(), Self::Error>;
}

pub fn read(path: &str) -> IOResult<Vec<u8>> {
	let mut buf = Vec::new();
	fs::File::open(path).map(|mut f| f.read_to_end(&mut buf))??;
	Ok(buf)
}

pub fn write(bytes: &[u8], path: &str) -> IOResult<()> {
	fs::File::create(path).map(|mut f| f.write_all(bytes))?
}

pub fn read_to_string(filepath: &str) -> IOResult<String> {
	let mut contents = String::new();
	fs::File::open(filepath).map(|mut f| f.read_to_string(&mut contents))??;
	Ok(contents)
}

#[cfg(feature = "sgx")]
mod sgx {
	use std::{
		io::{Read, Result, Write},
		sgxfs::SgxFile,
		vec::Vec,
	};

	pub fn unseal(path: &str) -> Result<Vec<u8>> {
		let mut buf = Vec::new();
		SgxFile::open(path).map(|mut f| f.read_to_end(&mut buf))??;
		Ok(buf)
	}

	pub fn seal(bytes: &[u8], path: &str) -> Result<()> {
		SgxFile::create(path).map(|mut f| f.write_all(bytes))?
	}
}
