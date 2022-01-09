use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionRequest<K: Serialize, R: Serialize> {
    pub account_public_key: K,

    #[serde(with = "super::b64wrap")]
    pub signed_authorization_request: R,
}

#[derive(Deserialize)]
pub struct ProvisionResult {
    #[serde(rename = "authorizationURL")]
    pub authorization_url: String,
    #[serde(rename = "provisionedChallengeURL")]
    pub provisioned_challenge_url: String,
}
