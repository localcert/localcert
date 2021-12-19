use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainRequest<R: Serialize> {
    #[serde(with = "super::b64wrap")]
    pub signed_account_request: R,
}

#[derive(Deserialize)]
pub struct DomainResult {
    pub domain: String,
}
