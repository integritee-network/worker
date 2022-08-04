//! Converts maps to vecs for serialization.
//! from https://github.com/DenisKolodin/vectorize
//!
//! `bypass` is necessary to force deriving serialization of complex type specs.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[allow(unused)]
pub fn serialize<'a, T, S>(target: T, ser: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
	T: Serialize + 'a,
{
	serde::Serialize::serialize(&target, ser)
}

#[allow(unused)]
pub fn deserialize<'de, T, D>(des: D) -> Result<T, D::Error>
where
	D: Deserializer<'de>,
	T: Deserialize<'de>,
{
	serde::Deserialize::deserialize(des)
}

#[cfg(test)]
mod tests {
	use serde::{de::DeserializeOwned, Deserialize, Serialize};
	use std::fmt;

	trait Requirement:
		DeserializeOwned + Serialize + Clone + fmt::Debug + Sync + Send + 'static
	{
	}

	trait ComplexSpec: Requirement {}

	#[derive(Debug, Serialize, Deserialize)]
	struct MyComplexType<T: ComplexSpec> {
		#[serde(with = "super")] // = "vectorize::bypass"
		inner: Option<T>,
	}
}
