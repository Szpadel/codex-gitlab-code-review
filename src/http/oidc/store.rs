//! Bounded session storage that admits new logins after the store fills.

use async_trait::async_trait;
use moka::{Expiry, future::Cache, policy::EvictionPolicy};
use std::time::{Duration, Instant};
use tower_sessions::{
    SessionStore,
    cookie::time::OffsetDateTime,
    session::{Id, Record},
    session_store,
};

/// Keeps session deadlines and evicts least-recently-used records at capacity.
/// Frequency-based admission can silently discard a new pending login, so it
/// cannot be used as the authoritative store for the OIDC callback.
#[derive(Clone, Debug)]
pub(super) struct OidcSessionStore {
    records: Cache<Id, Record>,
}

impl OidcSessionStore {
    /// Bounds process-local storage without rejecting newly created sessions.
    pub(super) fn new(capacity: u64) -> Self {
        Self {
            records: Cache::builder()
                .max_capacity(capacity)
                .eviction_policy(EvictionPolicy::lru())
                .expire_after(SessionExpiry)
                .build(),
        }
    }
}

#[async_trait]
impl SessionStore for OidcSessionStore {
    async fn create(&self, record: &mut Record) -> session_store::Result<()> {
        while self.records.contains_key(&record.id) {
            record.id = Id::default();
        }
        self.records.insert(record.id, record.clone()).await;
        Ok(())
    }

    async fn save(&self, record: &Record) -> session_store::Result<()> {
        self.records.insert(record.id, record.clone()).await;
        Ok(())
    }

    async fn load(&self, session_id: &Id) -> session_store::Result<Option<Record>> {
        Ok(self.records.get(session_id).await)
    }

    async fn delete(&self, session_id: &Id) -> session_store::Result<()> {
        self.records.invalidate(session_id).await;
        Ok(())
    }
}

struct SessionExpiry;

impl SessionExpiry {
    fn remaining(record: &Record) -> Duration {
        // A deadline in the past must expire immediately.
        (record.expiry_date - OffsetDateTime::now_utc())
            .try_into()
            .unwrap_or(Duration::ZERO)
    }
}

impl Expiry<Id, Record> for SessionExpiry {
    fn expire_after_create(&self, _: &Id, record: &Record, _: Instant) -> Option<Duration> {
        Some(Self::remaining(record))
    }

    fn expire_after_update(
        &self,
        _: &Id,
        record: &Record,
        _: Instant,
        _: Option<Duration>,
    ) -> Option<Duration> {
        Some(Self::remaining(record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, sync::Arc};
    use tower_sessions::{Expiry as SessionExpiry, Session};

    #[tokio::test]
    async fn full_store_retains_new_pending_and_authenticated_sessions() {
        let capacity = 32;
        let store = Arc::new(OidcSessionStore::new(capacity));
        for _ in 0..capacity {
            store
                .create(&mut Record {
                    id: Id::default(),
                    data: HashMap::new(),
                    expiry_date: OffsetDateTime::now_utc() + super::super::LOGIN_TIMEOUT,
                })
                .await
                .unwrap();
        }
        store.records.run_pending_tasks().await;
        assert_eq!(store.records.entry_count(), capacity);

        // Use tower-sessions' real save and rotation paths, as the OIDC handlers do.
        let session = Session::new(
            None,
            store.clone(),
            Some(SessionExpiry::OnInactivity(super::super::LOGIN_TIMEOUT)),
        );
        session
            .insert(super::super::PENDING_LOGIN, "pending")
            .await
            .unwrap();
        session.save().await.unwrap();
        store.records.run_pending_tasks().await;
        let pending = Session::new(session.id(), store.clone(), None);
        assert_eq!(
            pending
                .get::<String>(super::super::PENDING_LOGIN)
                .await
                .unwrap()
                .as_deref(),
            Some("pending")
        );

        session.cycle_id().await.unwrap();
        session
            .insert(super::super::AUTHENTICATED_UNTIL, 1_i64)
            .await
            .unwrap();
        session.save().await.unwrap();
        store.records.run_pending_tasks().await;
        let authenticated = Session::new(session.id(), store.clone(), None);
        assert_eq!(
            authenticated
                .get::<i64>(super::super::AUTHENTICATED_UNTIL)
                .await
                .unwrap(),
            Some(1)
        );
        assert!(store.records.entry_count() <= capacity);
    }
}
