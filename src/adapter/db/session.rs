use crate::application::{
    app_error::{AppError, AppResult},
    interface::db::DBSession
};
use async_trait::async_trait;
use futures::future::BoxFuture;
use sqlx::{Pool, Postgres, Transaction};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct SessionInner {
    pool: Pool<Postgres>,
    transaction: Option<Transaction<'static, Postgres>>,
}

#[derive(Clone)]
pub struct SqlxSession {
    inner: Arc<Mutex<SessionInner>>,
}

impl SqlxSession {
    pub async fn new(pool: Pool<Postgres>) -> AppResult<Self> {
        let tx = pool.begin().await?;

        Ok(Self {
            inner: Arc::new(Mutex::new(SessionInner {
                pool,
                transaction: Some(tx),
            })),
        })
    }

    pub fn new_lazy(pool: Pool<Postgres>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionInner {
                pool,
                transaction: None,
            })),
        }
    }

    pub async fn begin(&self) -> AppResult<()> {
        let mut inner = self.inner.lock().await;
        if inner.transaction.is_none() {
            let tx = inner.pool.begin().await?;
            inner.transaction = Some(tx);
        }
        Ok(())
    }

    pub async fn with_tx<F, T>(&self, f: F) -> AppResult<T>
    where
        F: for<'a> FnOnce(&'a mut Transaction<'static, Postgres>) -> BoxFuture<'a, AppResult<T>>,
    {
        let mut inner = self.inner.lock().await;
        if inner.transaction.is_none() {
            let tx = inner.pool.begin().await?;
            inner.transaction = Some(tx);
        }
        let tx = inner
            .transaction
            .as_mut()
            .ok_or_else(|| AppError::DatabaseError(sqlx::Error::PoolClosed))?;
        f(tx).await
    }
}

#[async_trait]
impl DBSession for SqlxSession {
    async fn commit(&self) -> AppResult<()> {
        let mut inner = self.inner.lock().await;
        if let Some(tx) = inner.transaction.take() {
            tx.commit().await?;
        }

        Ok(())
    }

    async fn rollback(&self) -> AppResult<()> {
        let mut inner = self.inner.lock().await;
        if let Some(tx) = inner.transaction.take() {
            tx.rollback().await?
        }

        Ok(())
    }
}
