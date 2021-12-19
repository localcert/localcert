use std::time::Duration;

use acme::{
    api::{
        account::Account,
        authorization::Authorization,
        challenge::ChallengeState,
        order::{GeneratedKey, Order, OrderState},
    },
    wire::{
        authorization::AuthorizationStatus, challenge::CHALLENGE_TYPE_DNS_01, order::OrderStatus,
    },
};
use async_timer::Oneshot;

use crate::{
    error::{LocalcertError, LocalcertResult},
    wire::client::LocalcertClient,
};

pub struct RegisteredState {
    client: LocalcertClient,
    account: Account,
    acme_polling_interval: Duration,
}

impl RegisteredState {
    pub(crate) fn new(
        client: LocalcertClient,
        account: Account,
        acme_polling_interval: Duration,
    ) -> Self {
        Self {
            client,
            account,
            acme_polling_interval,
        }
    }

    pub fn account(&self) -> &Account {
        &self.account
    }

    pub async fn new_order(self) -> LocalcertResult<OrderedState> {
        let domain_result = self.client.get_domain(&self.account).await?;
        let order = self.account.new_dns_order(domain_result.domain).await?;
        Ok(self.with_order(order))
    }

    pub fn with_order(self, acme_order: Order) -> OrderedState {
        OrderedState(State {
            client: self.client,
            account: self.account,
            order: acme_order,
            acme_polling_interval: self.acme_polling_interval,
        })
    }

    pub async fn resume_order(self, order_url: &str) -> LocalcertResult<ResumeOrderState> {
        let order = self.account.get_order(order_url).await?;
        let state = State {
            client: self.client,
            account: self.account,
            order,
            acme_polling_interval: self.acme_polling_interval,
        };
        Ok(match state.order.status_result()? {
            OrderStatus::Pending => ResumeOrderState::Ordered(OrderedState(state)),
            OrderStatus::Ready => ResumeOrderState::Authorized(AuthorizedState(state)),
            OrderStatus::Processing | OrderStatus::Valid => {
                ResumeOrderState::Finalized(FinalizedState(state))
            }
            _ => unreachable!(),
        })
    }
}

pub enum ResumeOrderState {
    Ordered(OrderedState),
    Authorized(AuthorizedState),
    Finalized(FinalizedState),
}

struct State {
    client: LocalcertClient,
    account: Account,
    order: Order,
    acme_polling_interval: Duration,
}

impl State {
    async fn order_status_changed_from(
        &mut self,
        status: OrderStatus,
    ) -> LocalcertResult<OrderStatus> {
        if self.order.status() == status {
            // TODO: timeout
            self.order
                .status_changed(|| {
                    <async_timer::oneshot::Timer as Oneshot>::new(self.acme_polling_interval)
                })
                .await?;
        }
        Ok(self.order.status_result()?)
    }
}

pub struct OrderedState(State);

impl OrderedState {
    pub fn order_url(&self) -> &str {
        self.0.order.url()
    }

    pub async fn authorize(mut self) -> LocalcertResult<AuthorizedState> {
        if let OrderState::Pending(ref pending) = self.0.order.state_result()? {
            let mut authorization = pending.get_only_authorization().await?;
            authorize(&self.0.client, &self.0.account, &mut authorization).await?;
            self.0
                .order_status_changed_from(OrderStatus::Pending)
                .await?;
        }
        Ok(AuthorizedState(self.0))
    }
}

pub struct AuthorizedState(State);

impl AuthorizedState {
    pub async fn finalize_with_generated_key(
        mut self,
    ) -> LocalcertResult<(GeneratedKey, FinalizedState)> {
        match self.0.order.state_result()? {
            OrderState::Ready(mut ready) => {
                let generated_key = ready.finalize_with_generated_key().await?;
                Ok((generated_key, FinalizedState(self.0)))
            }
            _ => Err(LocalcertError::unexpected_status(
                "order",
                self.0.order.status(),
            )),
        }
    }

    pub async fn finalize_with_csr(
        mut self,
        csr_der: impl AsRef<[u8]>,
    ) -> LocalcertResult<FinalizedState> {
        match self.0.order.state_result()? {
            OrderState::Ready(mut ready) => {
                ready.finalize(csr_der).await?;
            }
            OrderState::Pending(_) => {
                return Err(LocalcertError::unexpected_status(
                    "order",
                    self.0.order.status(),
                ))
            }
            _ => (),
        };
        Ok(FinalizedState(self.0))
    }
}

pub struct FinalizedState(State);

impl FinalizedState {
    pub async fn get_certificate(&mut self) -> LocalcertResult<String> {
        let status = self
            .0
            .order_status_changed_from(OrderStatus::Processing)
            .await?;
        match self.0.order.state_result()? {
            OrderState::Valid(ref valid) => Ok(valid.get_certificate_chain().await?),
            _ => return Err(LocalcertError::unexpected_status("order", status)),
        }
    }
}

async fn authorize(
    client: &LocalcertClient,
    account: &Account,
    authorization: &mut Authorization,
) -> LocalcertResult<()> {
    match authorization.status_result()? {
        AuthorizationStatus::Pending => (),
        AuthorizationStatus::Valid => {
            return Ok(());
        }
        _ => unreachable!(),
    }

    let mut challenge = authorization
        .find_challenge_type(CHALLENGE_TYPE_DNS_01)
        .ok_or(LocalcertError::AcmeFeatureMissing("no dns-01 challenge"))?;

    let provision_result = client
        .provision_domain(account, authorization.url())
        .await?;

    if &provision_result.provisioned_challenge_url != challenge.url() {
        return Err(LocalcertError::StateError(
            "provisioned challenge doesn't match DNS-01 challenge".to_string(),
        ));
    }

    if let ChallengeState::Pending(mut pending) = challenge.state_result()? {
        pending.respond().await?;
    }
    Ok(())
}
