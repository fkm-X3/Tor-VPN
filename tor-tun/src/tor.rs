use anyhow::Result;
use arti_client::{TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;

#[derive(Clone)]
pub struct TorHandle {
    pub client: TorClient<PreferredRuntime>,
}

pub async fn bootstrap() -> Result<TorHandle> {
    log::info!("Bootstrapping Tor client (this may take a while)...");
    let config = TorClientConfig::default();
    let client = TorClient::create_bootstrapped(config).await?;
    log::info!("Tor client bootstrapped successfully");
    Ok(TorHandle { client })
}
