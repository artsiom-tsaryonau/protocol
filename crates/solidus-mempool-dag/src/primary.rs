//! The primary's certificate pool: certified batch digests waiting to be
//! ordered. Consensus drafts from here at propose time
//! (`PayloadProvider`); commit notifications retire digests globally
//! (a digest committed in ANYONE's block is done); abandoned drafts
//! requeue.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::types::{BatchCertificate, BatchDigest};

/// Monotone draft generation (identifies a proposal attempt).
pub type DraftId = u64;

#[derive(Default)]
pub struct CertPool {
    queue: VecDeque<BatchCertificate>,
    queued: HashSet<BatchDigest>,
    in_flight: HashMap<DraftId, Vec<BatchCertificate>>,
    retired: HashSet<BatchDigest>,
    next_draft: DraftId,
}

impl CertPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a freshly formed certificate (dedup by digest; retired
    /// digests never re-enter).
    pub fn add(&mut self, cert: BatchCertificate) {
        if self.retired.contains(&cert.digest) || !self.queued.insert(cert.digest) {
            return;
        }
        self.queue.push_back(cert);
    }

    /// Draft up to `max` certificates for a proposal. The draft stays
    /// in-flight until committed or requeued.
    pub fn draft(&mut self, max: usize) -> (DraftId, Vec<BatchCertificate>) {
        let id = self.next_draft;
        self.next_draft += 1;
        let take = max.min(self.queue.len());
        let certs: Vec<BatchCertificate> = self.queue.drain(..take).collect();
        for c in &certs {
            self.queued.remove(&c.digest);
        }
        if !certs.is_empty() {
            self.in_flight.insert(id, certs.clone());
        }
        (id, certs)
    }

    /// A committed block carried these digests — retire them everywhere
    /// (queue, any in-flight draft, and permanently).
    pub fn on_committed(&mut self, digests: &[BatchDigest]) {
        for d in digests {
            self.retired.insert(*d);
            self.queued.remove(d);
        }
        self.queue.retain(|c| !self.retired.contains(&c.digest));
        for certs in self.in_flight.values_mut() {
            certs.retain(|c| !self.retired.contains(&c.digest));
        }
        self.in_flight.retain(|_, certs| !certs.is_empty());
    }

    /// A proposal was abandoned (view change, competing chain): its
    /// certificates go back to the front of the queue.
    pub fn requeue(&mut self, draft: DraftId) {
        if let Some(certs) = self.in_flight.remove(&draft) {
            for cert in certs.into_iter().rev() {
                if !self.retired.contains(&cert.digest) && self.queued.insert(cert.digest) {
                    self.queue.push_front(cert);
                }
            }
        }
    }

    /// Do we already hold or have we retired this digest?
    ///
    /// ⚠ EXISTS TO SKIP A BLS VERIFICATION, not for logic. Certificates are
    /// gossiped, so on a committee of N each one arrives N-1 times; verifying
    /// every copy costs an aggregate BLS check per duplicate. At high batch
    /// rates that was enough to slow the whole net measurably.
    pub fn knows(&self, digest: &BatchDigest) -> bool {
        self.retired.contains(digest) || self.queued.contains(digest)
    }

    pub fn pending(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(n: u8) -> BatchCertificate {
        BatchCertificate {
            digest: BatchDigest([n; 32]),
            worker: 0,
            attestation: vec![],
        }
    }

    #[test]
    fn draft_requeue_and_retire_lifecycle() {
        let mut pool = CertPool::new();
        pool.add(cert(1));
        pool.add(cert(2));
        pool.add(cert(1)); // dedup
        assert_eq!(pool.pending(), 2);

        let (draft, certs) = pool.draft(10);
        assert_eq!(certs.len(), 2);
        assert_eq!(pool.pending(), 0);

        // Abandoned → back in order.
        pool.requeue(draft);
        assert_eq!(pool.pending(), 2);

        // Draft again; this time block 1 commits digest 1.
        let (_d2, certs2) = pool.draft(1);
        assert_eq!(certs2[0].digest, BatchDigest([1; 32]));
        pool.on_committed(&[BatchDigest([1; 32])]);

        // Digest 1 never comes back, even if re-added or requeued.
        pool.add(cert(1));
        assert_eq!(pool.pending(), 1); // only cert 2
        let (_d3, certs3) = pool.draft(10);
        assert_eq!(certs3.len(), 1);
        assert_eq!(certs3[0].digest, BatchDigest([2; 32]));
    }

    #[test]
    fn committed_digest_clears_other_drafts() {
        let mut pool = CertPool::new();
        pool.add(cert(5));
        let (d1, _) = pool.draft(10);
        // Someone else's block commits digest 5.
        pool.on_committed(&[BatchDigest([5; 32])]);
        // Requeue of our stale draft brings nothing back.
        pool.requeue(d1);
        assert_eq!(pool.pending(), 0);
    }
}
