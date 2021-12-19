use acme::AcmeError;
use thiserror::Error;

pub type LocalcertResult<T> = Result<T, LocalcertError>;

#[derive(Error, Debug)]
pub enum LocalcertError {
    #[error(transparent)]
    AcmeError(#[from] AcmeError),

    #[error("ACME server missing required feature: {0}")]
    AcmeFeatureMissing(&'static str),

    #[error("http: [{}] {0}", .0.status())]
    HttpError(http_client::Error),

    #[error("invalid base URL: {0}")]
    InvalidBaseUrl(String),

    #[error("json: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("{0}")]
    StateError(String),
}

impl LocalcertError {
    pub(crate) fn unexpected_status(resource_type: &str, status: impl std::fmt::Debug) -> Self {
        Self::StateError(format!("unexpected {} status {:?}", resource_type, status))
    }
}

impl From<http_client::Error> for LocalcertError {
    fn from(err: http_client::Error) -> Self {
        Self::HttpError(err)
    }
}
