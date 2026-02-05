use crate::application::{
    app_error::{AppError, AppResult},
    interface::db::DBSession,
};
use async_trait::async_trait;
use futures::future::BoxFuture;
use sqlx::{Pool, Postgres, Transaction};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Fresh,
    Active,
    Committed,
}

struct SessionInner {
    pool: Pool<Postgres>,
    transaction: Option<Transaction<'static, Postgres>>,
    state: SessionState,
}

#[derive(Clone)]
pub struct SqlxSession {
    inner: Arc<Mutex<SessionInner>>,
}

impl SqlxSession {
    pub fn new_lazy(pool: Pool<Postgres>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionInner {
                pool,
                transaction: None,
                state: SessionState::Fresh,
            })),
        }
    }

    pub async fn with_tx<F, T>(&self, f: F) -> AppResult<T>
    where
        F: for<'a> FnOnce(&'a mut Transaction<'static, Postgres>) -> BoxFuture<'a, AppResult<T>>
            + Send,
        T: Send,
    {
        // TODO: Review the implementation (deadlock?)
        let mut inner = self.inner.lock().await;

        Self::ensure_usable(&inner)?;

        if inner.transaction.is_none() {
            let tx = inner.pool.begin().await?;
            inner.transaction = Some(tx);
            inner.state = SessionState::Active;
        }

        let tx = inner
            .transaction
            .as_mut()
            .ok_or_else(|| AppError::DatabaseError(sqlx::Error::PoolClosed))?;
        f(tx).await
    }

    fn ensure_usable(inner: &SessionInner) -> AppResult<()> {
        match inner.state {
            SessionState::Committed => Err(AppError::SessionAlreadyCommitted),
            _ => Ok(()),
        }
    }
}

#[async_trait]
impl DBSession for SqlxSession {
    async fn commit(&self) -> AppResult<()> {
        let mut inner = self.inner.lock().await;

        Self::ensure_usable(&inner)?;

        if let Some(tx) = inner.transaction.take() {
            tx.commit().await?;
        }
        inner.state = SessionState::Committed;

        Ok(())
    }
}
