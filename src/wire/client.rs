use std::{fmt::Display, sync::Arc};

use http_client::{http_types::Url, Body, HttpClient, Request};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::value::RawValue;

use acme::{
    api::account::Account,
    crypto::account_key::AccountKey,
    wire::{
        account::NewAccountResource,
        client::{Auth, NO_PAYLOAD},
        problem::AcmeProblemType,
    },
    AcmeError,
};

use super::{
    domain::{DomainRequest, DomainResult},
    provision::{ProvisionRequest, ProvisionResult},
};
use crate::error::{LocalcertError, LocalcertResult};

pub struct LocalcertClient {
    http: Arc<dyn HttpClient>,
    base_url: Url,
}

impl LocalcertClient {
    pub fn new<U>(http: impl Into<Arc<dyn HttpClient>>, base_url: U) -> LocalcertResult<Self>
    where
        U: TryInto<Url>,
        U::Error: Display,
    {
        let mut url = base_url
            .try_into()
            .map_err(|err| LocalcertError::InvalidBaseUrl(err.to_string()))?;

        // Ensure base_url ends with '/' so joins will work later
        url.path_segments_mut()
            .map_err(|_| LocalcertError::InvalidBaseUrl("cannot be a base URL".to_string()))?
            .pop_if_empty()
            .push("");

        Ok(Self {
            http: http.into(),
            base_url: url,
        })
    }

    pub async fn get_domain(&self, account: &Account) -> LocalcertResult<DomainResult> {
        let mut res = self.get_domain_once(account).await;
        if is_bad_nonce_error(&res) {
            res = self.get_domain_once(account).await;
        }
        res
    }

    async fn get_domain_once(&self, account: &Account) -> LocalcertResult<DomainResult> {
        let account_jwk = account.key().public_jwk().map_err(AcmeError::CryptoError)?;
        let signed_account_request = account
            .client()
            .build_request_body(
                account.key(),
                &account.client().directory().new_account,
                &Auth::Jwk(RawValue::from_string(account_jwk)?),
                &Some(NewAccountResource {
                    only_return_existing: true,
                    ..Default::default()
                }),
            )
            .await?;
        let domain_request = &DomainRequest {
            signed_account_request,
        };
        Ok(self.localcert_request("domain", domain_request).await?)
    }

    pub async fn provision_domain(
        &self,
        account: &Account,
        authorization_url: &str,
    ) -> LocalcertResult<ProvisionResult> {
        let mut res = self.provision_domain_once(account, authorization_url).await;
        if is_bad_nonce_error(&res) {
            res = self.provision_domain_once(account, authorization_url).await;
        }
        res
    }

    async fn provision_domain_once(
        &self,
        account: &Account,
        authorization_url: &str,
    ) -> LocalcertResult<ProvisionResult> {
        let signed_authorization_request = account
            .client()
            .build_request_body(
                account.key(),
                authorization_url,
                &Auth::kid(account.url()),
                &NO_PAYLOAD,
            )
            .await?;
        let public_jwk = account.key().public_jwk().map_err(AcmeError::CryptoError)?;
        let provision_request = &ProvisionRequest {
            signed_authorization_request,
            account_public_key: RawValue::from_string(public_jwk)?,
        };
        Ok(self
            .localcert_request("provision", provision_request)
            .await?)
    }

    async fn localcert_request<Res: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> LocalcertResult<Res> {
        let url = self.base_url.join(path).unwrap();
        let mut req = Request::post(url);
        req.set_body(Body::from_json(body)?);

        let mut resp = self.http.send(req).await?;

        let status = resp.status();
        if !status.is_success() {
            if let Ok(problem) = resp.body_json().await {
                return Err(AcmeError::AcmeProblem(problem).into());
            }
            return Err(http_client::Error::from_str(status, "").into());
        }

        Ok(resp.body_json().await?)
    }
}

pub(crate) fn is_bad_nonce_error<T>(res: &LocalcertResult<T>) -> bool {
    if let Err(LocalcertError::AcmeError(AcmeError::AcmeProblem(ref problem))) = res {
        problem.has_type(AcmeProblemType::BadNonce)
    } else {
        false
    }
}
