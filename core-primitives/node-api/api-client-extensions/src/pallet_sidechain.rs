use crate::ApiResult;
use itp_api_client_types::{traits::GetStorage, Api, Config, Request};
use itp_types::{parentchain::SidechainBlockConfirmation, ShardIdentifier};

pub const SIDECHAIN: &str = "Sidechain";

pub trait PalletSidechainApi {
	type Hash;

	fn latest_sidechain_block_confirmation(
		&self,
		shard: &ShardIdentifier,
		at_block: Option<Self::Hash>,
	) -> ApiResult<Option<SidechainBlockConfirmation>>;
}

impl<RuntimeConfig, Client> PalletSidechainApi for Api<RuntimeConfig, Client>
where
	RuntimeConfig: Config,
	Client: Request,
{
	type Hash = RuntimeConfig::Hash;

	fn latest_sidechain_block_confirmation(
		&self,
		shard: &ShardIdentifier,
		at_block: Option<Self::Hash>,
	) -> ApiResult<Option<SidechainBlockConfirmation>> {
		self.get_storage_map(SIDECHAIN, "LatestSidechainBlockConfirmation", shard, at_block)
	}
}
