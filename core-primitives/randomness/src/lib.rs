#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "sgx")]
use sgx_rand::{thread_rng, Rng};

pub trait Randomness {
	fn shuffle<T>(values: &mut [T]);
	fn random_u32(min: u32, max: u32) -> u32;
}

pub struct SgxRandomness;

#[cfg(feature = "sgx")]
impl Randomness for SgxRandomness {
	/// Use SGX's true RNG to shuffle the values.
	fn shuffle<T>(values: &mut [T]) {
		let mut rng = thread_rng(); // Use thread-local random number generator
		rng.shuffle(values);
	}

	fn random_u32(min: u32, max: u32) -> u32 {
		let mut rng = thread_rng(); // Use thread-local random number generator
		rng.gen_range(min, max)
	}
}

#[cfg(not(feature = "sgx"))]
impl Randomness for SgxRandomness {
	fn shuffle<T>(_values: &mut [T]) {
		unimplemented!()
	}

	fn random_u32(_min: u32, _max: u32) -> u32 {
		unimplemented!()
	}
}

pub struct MockRandomness;

impl Randomness for MockRandomness {
	/// Switch the first two values if there are at least two values.
	fn shuffle<T>(values: &mut [T]) {
		if values.len() > 1 {
			values.swap(0, 1);
		}
	}

	/// return the average as a deterministic mock value in the desired range
	fn random_u32(min: u32, max: u32) -> u32 {
		min + max / 2
	}
}
