pub mod error;
pub mod states;
pub mod wire;

use std::{sync::Arc, time::Duration};

use acme::{
    api::{account::Account, acme_server::RegisterAccountConfig},
    AcmeServer,
};
use error::LocalcertResult;
use http_client::HttpClient;
use states::RegisteredState;
use wire::client::LocalcertClient;

pub static DEFAULT_SERVER_URL: &str = "https://localcert.dev";
pub static DEFAULT_ACME_POLLING_INTERVAL: Duration = Duration::from_secs(5);

pub struct ConfigBuilder {
    http_client: Arc<dyn HttpClient>,
    server_url: Option<String>,
    acme_polling_interval: Duration,
}

impl ConfigBuilder {
    #[cfg(feature = "http_native_client")]
    pub fn new() -> Self {
        Self::with_http_client(http_client::native::NativeClient::new())
    }

    pub fn with_http_client(http_client: impl HttpClient) -> Self {
        Self {
            http_client: Arc::new(http_client),
            server_url: None,
            acme_polling_interval: DEFAULT_ACME_POLLING_INTERVAL,
        }
    }

    pub fn localcert_server_url(&mut self, server_url: impl Into<String>) -> &mut Self {
        self.server_url = Some(server_url.into());
        self
    }

    pub fn acme_polling_interval(&mut self, interval: impl Into<Duration>) -> &mut Self {
        self.acme_polling_interval = interval.into();
        self
    }

    pub async fn register_new_account(
        self,
        acme_directory_url: &str,
        register_config: RegisterAccountConfig,
    ) -> LocalcertResult<RegisteredState> {
        let server =
            AcmeServer::for_directory_url(self.http_client.clone(), acme_directory_url).await?;
        let account = server.register_account_config(register_config).await?;
        self.build_with_account(account)
    }

    pub fn build_with_account(self, acme_account: Account) -> LocalcertResult<RegisteredState> {
        let base_url = self.server_url.as_deref().unwrap_or(DEFAULT_SERVER_URL);
        let client = LocalcertClient::new(self.http_client, base_url)?;
        Ok(RegisteredState::new(
            client,
            acme_account,
            self.acme_polling_interval,
        ))
    }
}
