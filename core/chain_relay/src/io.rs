#[derive(Copy, Clone, Debug, Display)]
pub struct AesSeal;

impl SealedIO for AesSeal {
	type Error = Error;
	type Unsealed = Aes;

	fn unseal() -> Result<Self::Unsealed> {
		Ok(unseal(AES_KEY_FILE_AND_INIT_V).map(|b| Decode::decode(&mut b.as_slice()))??)
	}

	fn seal(unsealed: Self::Unsealed) -> Result<()> {
		Ok(unsealed.using_encoded(|bytes| seal(bytes, AES_KEY_FILE_AND_INIT_V))?)
	}
}

pub fn unseal() -> Result<LightValidation> {
	let vec = super::unseal(CHAIN_RELAY_DB)?;
	Ok(LightValidation::decode(&mut vec.as_slice())?)
}

pub fn seal(validator: LightValidation) -> Result<()> {
	debug!("backup chain relay state");
	if fs::copy(CHAIN_RELAY_DB, format!("{}.1", CHAIN_RELAY_DB)).is_err() {
		warn!("could not backup previous chain relay state");
	};
	debug!("Seal Chain Relay State. Current state: {:?}", validator);
	Ok(super::seal(validator.encode().as_slice(), CHAIN_RELAY_DB)?)
}

pub fn read_or_init_validator(
	header: Header,
	auth: VersionedAuthorityList,
	proof: StorageProof,
) -> Result<Header> {
	if SgxFile::open(CHAIN_RELAY_DB).is_err() {
		info!("[Enclave] ChainRelay DB not found, creating new! {}", CHAIN_RELAY_DB);
		return init_validator(header, auth, proof)
	}

	let validator = unseal().sgx_error_with_log("Error reading validator")?;

	let genesis = validator.genesis_hash(validator.num_relays()).unwrap();
	if genesis == header.hash() {
		info!("Found already initialized chain relay with Genesis Hash: {:?}", genesis);
		info!("Chain Relay state: {:?}", validator);
		Ok(validator.latest_finalized_header(validator.num_relays()).unwrap())
	} else {
		init_validator(header, auth, proof)
	}
}

fn init_validator(
	header: Header,
	auth: VersionedAuthorityList,
	proof: StorageProof,
) -> Result<Header> {
	let mut validator = LightValidation::new();

	validator.initialize_relay(header, auth.into(), proof).sgx_error()?;
	super::seal(validator.encode().as_slice(), CHAIN_RELAY_DB)?;

	Ok(validator.latest_finalized_header(validator.num_relays()).unwrap())
}
