use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainRequest<R: Serialize> {
    #[serde(with = "super::b64wrap")]
    pub signed_account_request: R,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainResult {
    pub localcert_domain: String,
}
