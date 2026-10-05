//! The connection pools: a few connections per endpoint, a place on one
//! per stream.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{Notify, OnceCell};

use super::link::Link;
use super::lock;
use crate::addr::PrivateAddrs;

/// What makes two connections interchangeable: the endpoint as configured,
/// and the pool's sizing. Secrets are fixed for a snapshot, so the raw
/// header templates stand for their values.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct PoolKey {
    pub(super) url: String,
    pub(super) headers: Vec<(String, String)>,
    pub(super) private: PrivateAddrs,
    pub(super) max_connections: usize,
    pub(super) max_streams: usize,
}

/// The service-layer connection pools of one policy snapshot.
#[derive(Default)]
pub(crate) struct Pools {
    pub(super) by_key: Mutex<HashMap<PoolKey, Arc<Pool>>>,
    pub(super) retired: AtomicBool,
}

impl Pools {
    /// A reload replaced this snapshot: its connections close once idle
    /// (now, for those that are). Client connections can hold an old
    /// snapshot for as long as they last, so this does not wait for it to
    /// be dropped.
    pub(crate) fn retire(&self) {
        self.retired.store(true, Ordering::SeqCst);
        for pool in lock(&self.by_key).values() {
            pool.retired.store(true, Ordering::SeqCst);
            lock(&pool.entries).retain(|e| e.reserved > 0);
        }
    }
}

pub(super) struct Pool {
    pub(super) entries: Mutex<Vec<Entry>>,
    /// A stream ended or a connection went away: waiters may find room.
    pub(super) freed: Notify,
    pub(super) max_connections: usize,
    pub(super) max_streams: usize,
    /// Its snapshot was replaced: connections close once idle.
    pub(super) retired: AtomicBool,
}

/// One connection of a pool. It counts against `max_connections` for as
/// long as anything holds a place on it, closed or not.
pub(super) struct Entry {
    pub(super) link: Arc<OnceCell<Arc<Link>>>,
    /// Streams on it, and exchanges waiting for it to connect.
    pub(super) reserved: usize,
}

impl Entry {
    /// Takes no new streams: its connection failed, or ran out of ids.
    pub(super) fn closed(&self) -> bool {
        self.link.get().is_some_and(|l| l.shared.closed())
    }
}

/// A place on one of the pool's connections, held until the stream ends.
pub(super) struct Reservation {
    pub(super) pool: Arc<Pool>,
    pub(super) link: Arc<OnceCell<Arc<Link>>>,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut entries = lock(&self.pool.entries);
        if let Some(i) = entries
            .iter()
            .position(|e| Arc::ptr_eq(&e.link, &self.link))
        {
            let e = &mut entries[i];
            e.reserved = e.reserved.saturating_sub(1);
            // Nobody is left on it, and it will take no one new: it never
            // connected, it closed, or its pool is retired.
            if e.reserved == 0
                && (e.link.get().is_none()
                    || e.closed()
                    || self.pool.retired.load(Ordering::SeqCst))
            {
                entries.remove(i);
            }
        }
        drop(entries);
        self.pool.freed.notify_waiters();
    }
}

impl Pool {
    /// A place on a connection with room, opening a new entry when every
    /// open one is full and the pool is not; else waits for one to free.
    pub(super) async fn reserve(self: &Arc<Self>) -> Reservation {
        loop {
            let freed = self.freed.notified();
            tokio::pin!(freed);
            freed.as_mut().enable();
            {
                let mut entries = lock(&self.entries);
                entries.retain(|e| e.reserved > 0 || !e.closed());
                let pick = if let Some(e) = entries
                    .iter_mut()
                    .find(|e| !e.closed() && e.reserved < self.max_streams)
                {
                    e.reserved += 1;
                    Some(e.link.clone())
                } else if entries.len() < self.max_connections {
                    let link = Arc::new(OnceCell::new());
                    entries.push(Entry {
                        link: link.clone(),
                        reserved: 1,
                    });
                    Some(link)
                } else {
                    None
                };
                if let Some(link) = pick {
                    return Reservation {
                        pool: self.clone(),
                        link,
                    };
                }
            }
            freed.await;
        }
    }
}
