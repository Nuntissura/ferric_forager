//! Atomic coupled-resource and byte-credit accounting models.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub use fforager_contracts::DurabilityPosition;

/// The complete coupled resource claim for one executable node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResourceVector {
    pub metadata_requests: u32,
    pub media_requests: u32,
    pub memory_bytes: u64,
    pub disk_read_bytes_in_flight: u64,
    pub disk_write_bytes_in_flight: u64,
    pub open_handles: u32,
    pub cpu_light_slots: u32,
    pub cpu_heavy_slots: u32,
    pub javascript_workers: u32,
    pub ffmpeg_processes: u32,
    pub ffmpeg_cpu_threads: u32,
    pub archive_writer_slots: u32,
    pub sink_bytes: u64,
}

impl ResourceVector {
    /// Checked component-wise addition. No dimension may wrap.
    #[must_use]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        Some(Self {
            metadata_requests: self.metadata_requests.checked_add(rhs.metadata_requests)?,
            media_requests: self.media_requests.checked_add(rhs.media_requests)?,
            memory_bytes: self.memory_bytes.checked_add(rhs.memory_bytes)?,
            disk_read_bytes_in_flight: self
                .disk_read_bytes_in_flight
                .checked_add(rhs.disk_read_bytes_in_flight)?,
            disk_write_bytes_in_flight: self
                .disk_write_bytes_in_flight
                .checked_add(rhs.disk_write_bytes_in_flight)?,
            open_handles: self.open_handles.checked_add(rhs.open_handles)?,
            cpu_light_slots: self.cpu_light_slots.checked_add(rhs.cpu_light_slots)?,
            cpu_heavy_slots: self.cpu_heavy_slots.checked_add(rhs.cpu_heavy_slots)?,
            javascript_workers: self
                .javascript_workers
                .checked_add(rhs.javascript_workers)?,
            ffmpeg_processes: self.ffmpeg_processes.checked_add(rhs.ffmpeg_processes)?,
            ffmpeg_cpu_threads: self
                .ffmpeg_cpu_threads
                .checked_add(rhs.ffmpeg_cpu_threads)?,
            archive_writer_slots: self
                .archive_writer_slots
                .checked_add(rhs.archive_writer_slots)?,
            sink_bytes: self.sink_bytes.checked_add(rhs.sink_bytes)?,
        })
    }

    /// Checked component-wise subtraction. No dimension may underflow.
    #[must_use]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        Some(Self {
            metadata_requests: self.metadata_requests.checked_sub(rhs.metadata_requests)?,
            media_requests: self.media_requests.checked_sub(rhs.media_requests)?,
            memory_bytes: self.memory_bytes.checked_sub(rhs.memory_bytes)?,
            disk_read_bytes_in_flight: self
                .disk_read_bytes_in_flight
                .checked_sub(rhs.disk_read_bytes_in_flight)?,
            disk_write_bytes_in_flight: self
                .disk_write_bytes_in_flight
                .checked_sub(rhs.disk_write_bytes_in_flight)?,
            open_handles: self.open_handles.checked_sub(rhs.open_handles)?,
            cpu_light_slots: self.cpu_light_slots.checked_sub(rhs.cpu_light_slots)?,
            cpu_heavy_slots: self.cpu_heavy_slots.checked_sub(rhs.cpu_heavy_slots)?,
            javascript_workers: self
                .javascript_workers
                .checked_sub(rhs.javascript_workers)?,
            ffmpeg_processes: self.ffmpeg_processes.checked_sub(rhs.ffmpeg_processes)?,
            ffmpeg_cpu_threads: self
                .ffmpeg_cpu_threads
                .checked_sub(rhs.ffmpeg_cpu_threads)?,
            archive_writer_slots: self
                .archive_writer_slots
                .checked_sub(rhs.archive_writer_slots)?,
            sink_bytes: self.sink_bytes.checked_sub(rhs.sink_bytes)?,
        })
    }

    #[must_use]
    pub fn fits_within(self, capacity: Self) -> bool {
        self.metadata_requests <= capacity.metadata_requests
            && self.media_requests <= capacity.media_requests
            && self.memory_bytes <= capacity.memory_bytes
            && self.disk_read_bytes_in_flight <= capacity.disk_read_bytes_in_flight
            && self.disk_write_bytes_in_flight <= capacity.disk_write_bytes_in_flight
            && self.open_handles <= capacity.open_handles
            && self.cpu_light_slots <= capacity.cpu_light_slots
            && self.cpu_heavy_slots <= capacity.cpu_heavy_slots
            && self.javascript_workers <= capacity.javascript_workers
            && self.ffmpeg_processes <= capacity.ffmpeg_processes
            && self.ffmpeg_cpu_threads <= capacity.ffmpeg_cpu_threads
            && self.archive_writer_slots <= capacity.archive_writer_slots
            && self.sink_bytes <= capacity.sink_bytes
    }

    fn variable_bytes(self) -> Option<u64> {
        self.memory_bytes
            .checked_add(self.disk_read_bytes_in_flight)?
            .checked_add(self.disk_write_bytes_in_flight)?
            .checked_add(self.sink_bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OwnerId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GrantId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WaiterId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub id: GrantId,
    pub owner: OwnerId,
    pub resources: ResourceVector,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Granted(Grant),
    Queued(WaiterId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    RequestExceedsCapacity,
    QueueItemLimit,
    QueueByteLimit,
    ArithmeticOverflow,
    IdExhausted,
    UnknownGrant(GrantId),
    GrantAlreadyReleased(GrantId),
    GrantOwnerMismatch { expected: OwnerId, actual: OwnerId },
    UnknownWaiter(WaiterId),
    InvariantViolation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Waiter {
    id: WaiterId,
    owner: OwnerId,
    resources: ResourceVector,
    variable_bytes: u64,
}

/// A deterministic FIFO broker with all-or-nothing coupled admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceLedger {
    capacity: ResourceVector,
    in_use: ResourceVector,
    active: BTreeMap<GrantId, Grant>,
    waiters: VecDeque<Waiter>,
    max_active_grants: usize,
    max_active_per_owner: usize,
    max_waiters: usize,
    max_waiter_bytes: u64,
    waiter_bytes: u64,
    next_grant: u64,
    next_waiter: u64,
}

impl ResourceLedger {
    #[must_use]
    pub fn new(
        capacity: ResourceVector,
        max_active_grants: usize,
        max_waiters: usize,
        max_waiter_bytes: u64,
    ) -> Self {
        Self {
            capacity,
            in_use: ResourceVector::default(),
            active: BTreeMap::new(),
            waiters: VecDeque::new(),
            max_active_grants,
            max_active_per_owner: max_active_grants.div_ceil(2),
            max_waiters,
            max_waiter_bytes,
            waiter_bytes: 0,
            next_grant: 1,
            next_waiter: 1,
        }
    }

    #[must_use]
    pub fn in_use(&self) -> ResourceVector {
        self.in_use
    }

    #[must_use]
    pub fn waiter_occupancy(&self) -> (usize, u64) {
        (self.waiters.len(), self.waiter_bytes)
    }

    /// Atomically grant or boundedly queue the complete vector.
    ///
    /// # Errors
    ///
    /// Returns a typed capacity, bound, arithmetic, or identity error.
    pub fn request(
        &mut self,
        owner: OwnerId,
        resources: ResourceVector,
    ) -> Result<Admission, LedgerError> {
        if !resources.fits_within(self.capacity) {
            return Err(LedgerError::RequestExceedsCapacity);
        }
        if self.waiters.is_empty()
            && self.active.len() < self.max_active_grants
            && self.owner_active_count(owner) < self.max_active_per_owner
            && self.can_grant(resources)
        {
            return self.issue(owner, resources).map(Admission::Granted);
        }
        if self.waiters.len() >= self.max_waiters {
            return Err(LedgerError::QueueItemLimit);
        }
        let variable_bytes = resources
            .variable_bytes()
            .ok_or(LedgerError::ArithmeticOverflow)?;
        let new_waiter_bytes = self
            .waiter_bytes
            .checked_add(variable_bytes)
            .ok_or(LedgerError::ArithmeticOverflow)?;
        if new_waiter_bytes > self.max_waiter_bytes {
            return Err(LedgerError::QueueByteLimit);
        }
        let id = WaiterId(self.next_waiter);
        self.next_waiter = self
            .next_waiter
            .checked_add(1)
            .ok_or(LedgerError::IdExhausted)?;
        self.waiters.push_back(Waiter {
            id,
            owner,
            resources,
            variable_bytes,
        });
        self.waiter_bytes = new_waiter_bytes;
        Ok(Admission::Queued(id))
    }

    /// Cancel a queued request and dispatch newly unblocked FIFO waiters.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown waiter or broken accounting invariant.
    pub fn cancel_waiter(&mut self, id: WaiterId) -> Result<Vec<Grant>, LedgerError> {
        let mut candidate = self.clone();
        let issued = candidate.cancel_waiter_checked(id)?;
        *self = candidate;
        Ok(issued)
    }

    fn cancel_waiter_checked(&mut self, id: WaiterId) -> Result<Vec<Grant>, LedgerError> {
        let Some(position) = self.waiters.iter().position(|waiter| waiter.id == id) else {
            return Err(LedgerError::UnknownWaiter(id));
        };
        let Some(waiter) = self.waiters.remove(position) else {
            return Err(LedgerError::InvariantViolation);
        };
        self.waiter_bytes = self
            .waiter_bytes
            .checked_sub(waiter.variable_bytes)
            .ok_or(LedgerError::InvariantViolation)?;
        self.drain_waiters()
    }

    /// Release exactly one owned grant and admit FIFO waiters that now fit.
    ///
    /// # Errors
    ///
    /// Returns a typed unknown, duplicate, ownership, or invariant error.
    pub fn release(&mut self, id: GrantId, owner: OwnerId) -> Result<Vec<Grant>, LedgerError> {
        let mut candidate = self.clone();
        let issued = candidate.release_checked(id, owner)?;
        *self = candidate;
        Ok(issued)
    }

    fn release_checked(&mut self, id: GrantId, owner: OwnerId) -> Result<Vec<Grant>, LedgerError> {
        let Some(grant) = self.active.get(&id).copied() else {
            return if id.0 > 0 && id.0 < self.next_grant {
                Err(LedgerError::GrantAlreadyReleased(id))
            } else {
                Err(LedgerError::UnknownGrant(id))
            };
        };
        if grant.owner != owner {
            return Err(LedgerError::GrantOwnerMismatch {
                expected: grant.owner,
                actual: owner,
            });
        }
        self.in_use = self
            .in_use
            .checked_sub(grant.resources)
            .ok_or(LedgerError::InvariantViolation)?;
        self.active.remove(&id);
        self.drain_waiters()
    }

    /// Recompute all accounting and bounds from the exact active identities.
    ///
    /// # Errors
    ///
    /// Returns `InvariantViolation` for any mismatch or exceeded bound.
    pub fn verify(&self) -> Result<(), LedgerError> {
        let mut sum = ResourceVector::default();
        for grant in self.active.values() {
            sum = sum
                .checked_add(grant.resources)
                .ok_or(LedgerError::InvariantViolation)?;
        }
        let bytes = self.waiters.iter().try_fold(0_u64, |total, waiter| {
            total.checked_add(waiter.variable_bytes)
        });
        if sum != self.in_use
            || !self.in_use.fits_within(self.capacity)
            || bytes != Some(self.waiter_bytes)
            || self.active.len() > self.max_active_grants
            || self
                .active
                .values()
                .map(|grant| grant.owner)
                .collect::<BTreeSet<_>>()
                .iter()
                .any(|owner| self.owner_active_count(*owner) > self.max_active_per_owner)
            || self.waiters.len() > self.max_waiters
            || self.waiter_bytes > self.max_waiter_bytes
        {
            return Err(LedgerError::InvariantViolation);
        }
        Ok(())
    }

    fn can_grant(&self, resources: ResourceVector) -> bool {
        let Some(combined) = self.in_use.checked_add(resources) else {
            return false;
        };
        combined.fits_within(self.capacity)
    }

    fn issue(&mut self, owner: OwnerId, resources: ResourceVector) -> Result<Grant, LedgerError> {
        let combined = self
            .in_use
            .checked_add(resources)
            .ok_or(LedgerError::ArithmeticOverflow)?;
        if !combined.fits_within(self.capacity) {
            return Err(LedgerError::RequestExceedsCapacity);
        }
        let id = GrantId(self.next_grant);
        self.next_grant = self
            .next_grant
            .checked_add(1)
            .ok_or(LedgerError::IdExhausted)?;
        let grant = Grant {
            id,
            owner,
            resources,
        };
        self.active.insert(id, grant);
        self.in_use = combined;
        Ok(grant)
    }

    fn drain_waiters(&mut self) -> Result<Vec<Grant>, LedgerError> {
        let mut issued = Vec::new();
        while self.active.len() < self.max_active_grants {
            let Some(waiter) = self.waiters.front().copied() else {
                break;
            };
            if self.owner_active_count(waiter.owner) >= self.max_active_per_owner
                || !self.can_grant(waiter.resources)
            {
                break;
            }
            let Some(waiter) = self.waiters.pop_front() else {
                return Err(LedgerError::InvariantViolation);
            };
            self.waiter_bytes = self
                .waiter_bytes
                .checked_sub(waiter.variable_bytes)
                .ok_or(LedgerError::InvariantViolation)?;
            issued.push(self.issue(waiter.owner, waiter.resources)?);
        }
        Ok(issued)
    }

    fn owner_active_count(&self, owner: OwnerId) -> usize {
        self.active
            .values()
            .filter(|grant| grant.owner == owner)
            .count()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreditError {
    ZeroClaim,
    CapacityExceeded,
    ClaimItemLimit,
    ArithmeticOverflow,
    IdExhausted,
    UnknownClaim(u64),
    ClaimAlreadyReleased(u64),
    ClaimOwnerMismatch,
    ReceivedBytesRequireClaim,
    PositionRegressed,
    WrittenAheadOfReceived,
    DurableAheadOfWritten,
    UncreditedBytes { received: u64, credited: u64 },
}

/// Bounded byte ownership plus monotonic durable-prefix accounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ByteCreditLedger {
    capacity: u64,
    in_use: u64,
    next_claim: u64,
    max_claims: usize,
    active: BTreeMap<u64, ByteClaim>,
    credited_total: u64,
    position: DurabilityPosition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ByteClaim {
    owner: OwnerId,
    bytes: u64,
    consumed: u64,
}

/// Auditable ownership and consumption state for one live byte claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreditAttribution {
    pub claim_id: u64,
    pub owner: OwnerId,
    pub bytes: u64,
    pub consumed: u64,
}

impl ByteCreditLedger {
    #[must_use]
    pub fn new(capacity: u64, max_claims: usize) -> Self {
        Self {
            capacity,
            in_use: 0,
            next_claim: 1,
            max_claims,
            active: BTreeMap::new(),
            credited_total: 0,
            position: DurabilityPosition::default(),
        }
    }

    /// Reserve a positive bounded byte claim.
    ///
    /// # Errors
    ///
    /// Returns a typed item, byte, arithmetic, or identity-bound error.
    pub fn claim(&mut self, owner: OwnerId, bytes: u64) -> Result<u64, CreditError> {
        if bytes == 0 {
            return Err(CreditError::ZeroClaim);
        }
        if self.active.len() >= self.max_claims {
            return Err(CreditError::ClaimItemLimit);
        }
        let combined = self
            .in_use
            .checked_add(bytes)
            .ok_or(CreditError::ArithmeticOverflow)?;
        if combined > self.capacity {
            return Err(CreditError::CapacityExceeded);
        }
        let credited_total = self
            .credited_total
            .checked_add(bytes)
            .ok_or(CreditError::ArithmeticOverflow)?;
        let id = self.next_claim;
        self.next_claim = self
            .next_claim
            .checked_add(1)
            .ok_or(CreditError::IdExhausted)?;
        self.active.insert(
            id,
            ByteClaim {
                owner,
                bytes,
                consumed: 0,
            },
        );
        self.in_use = combined;
        self.credited_total = credited_total;
        Ok(id)
    }

    /// Transfer exact claim ownership without changing the conserved byte total.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown, released, or differently owned claim.
    pub fn transfer(&mut self, id: u64, from: OwnerId, to: OwnerId) -> Result<(), CreditError> {
        let Some(claim) = self.active.get(&id).copied() else {
            return self.missing_claim(id);
        };
        if claim.owner != from {
            return Err(CreditError::ClaimOwnerMismatch);
        }
        self.active.insert(id, ByteClaim { owner: to, ..claim });
        Ok(())
    }

    /// Release exactly one byte claim and return its final attribution receipt.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown, duplicate, or differently owned claim.
    pub fn release(&mut self, id: u64, owner: OwnerId) -> Result<CreditAttribution, CreditError> {
        let Some(claim) = self.active.get(&id).copied() else {
            return self.missing_claim(id);
        };
        if owner != claim.owner {
            return Err(CreditError::ClaimOwnerMismatch);
        }
        self.in_use = self
            .in_use
            .checked_sub(claim.bytes)
            .ok_or(CreditError::ArithmeticOverflow)?;
        let unused = claim
            .bytes
            .checked_sub(claim.consumed)
            .ok_or(CreditError::ArithmeticOverflow)?;
        self.credited_total = self
            .credited_total
            .checked_sub(unused)
            .ok_or(CreditError::ArithmeticOverflow)?;
        self.active.remove(&id);
        Ok(CreditAttribution {
            claim_id: id,
            owner: claim.owner,
            bytes: claim.bytes,
            consumed: claim.consumed,
        })
    }

    /// Consume received bytes from exactly one owned claim.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown, released, differently owned, regressing,
    /// or insufficient claim. Failure does not mutate accounting.
    pub fn receive(
        &mut self,
        id: u64,
        owner: OwnerId,
        received_bytes: u64,
    ) -> Result<(), CreditError> {
        if received_bytes < self.position.received_bytes {
            return Err(CreditError::PositionRegressed);
        }
        let Some(claim) = self.active.get(&id).copied() else {
            return self.missing_claim(id);
        };
        if claim.owner != owner {
            return Err(CreditError::ClaimOwnerMismatch);
        }
        let newly_received = received_bytes
            .checked_sub(self.position.received_bytes)
            .ok_or(CreditError::PositionRegressed)?;
        let available = claim
            .bytes
            .checked_sub(claim.consumed)
            .ok_or(CreditError::ArithmeticOverflow)?;
        if newly_received > available {
            let credited = self
                .position
                .received_bytes
                .checked_add(available)
                .ok_or(CreditError::ArithmeticOverflow)?;
            return Err(CreditError::UncreditedBytes {
                received: received_bytes,
                credited,
            });
        }
        let consumed = claim
            .consumed
            .checked_add(newly_received)
            .ok_or(CreditError::ArithmeticOverflow)?;
        self.active.insert(id, ByteClaim { consumed, ..claim });
        self.position.received_bytes = received_bytes;
        Ok(())
    }

    /// Advance validated and durable prefixes monotonically after owned receive.
    ///
    /// # Errors
    ///
    /// Returns an error for regression, written-ahead, or durable-ahead state.
    pub fn advance(&mut self, next: DurabilityPosition) -> Result<(), CreditError> {
        if next.received_bytes < self.position.received_bytes
            || next.validated_bytes < self.position.validated_bytes
            || next.durable_bytes < self.position.durable_bytes
        {
            return Err(CreditError::PositionRegressed);
        }
        if next.received_bytes != self.position.received_bytes {
            return Err(CreditError::ReceivedBytesRequireClaim);
        }
        if next.validated_bytes > next.received_bytes {
            return Err(CreditError::WrittenAheadOfReceived);
        }
        if next.durable_bytes > next.validated_bytes {
            return Err(CreditError::DurableAheadOfWritten);
        }
        self.position = next;
        Ok(())
    }

    /// Return the live claim attribution used to audit owner-bound consumption.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown or released claim.
    pub fn attribution(&self, id: u64) -> Result<CreditAttribution, CreditError> {
        let Some(claim) = self.active.get(&id).copied() else {
            return self.missing_claim(id);
        };
        Ok(CreditAttribution {
            claim_id: id,
            owner: claim.owner,
            bytes: claim.bytes,
            consumed: claim.consumed,
        })
    }

    #[must_use]
    pub fn in_use(&self) -> u64 {
        self.in_use
    }

    #[must_use]
    pub fn position(&self) -> DurabilityPosition {
        self.position
    }

    /// Verify byte conservation, item bounds, and durability ordering.
    ///
    /// # Errors
    ///
    /// Returns an error when any accounting invariant is false.
    pub fn verify(&self) -> Result<(), CreditError> {
        let total = self
            .active
            .values()
            .try_fold(0_u64, |sum, claim| sum.checked_add(claim.bytes));
        let available = self.active.values().try_fold(0_u64, |sum, claim| {
            let remaining = claim.bytes.checked_sub(claim.consumed)?;
            sum.checked_add(remaining)
        });
        if total != Some(self.in_use)
            || self.in_use > self.capacity
            || self.active.len() > self.max_claims
            || self.position.validated_bytes > self.position.received_bytes
            || self.position.durable_bytes > self.position.validated_bytes
            || self.position.received_bytes > self.credited_total
            || available.and_then(|available| self.position.received_bytes.checked_add(available))
                != Some(self.credited_total)
        {
            return Err(CreditError::ArithmeticOverflow);
        }
        Ok(())
    }

    fn missing_claim<T>(&self, id: u64) -> Result<T, CreditError> {
        if id > 0 && id < self.next_claim {
            Err(CreditError::ClaimAlreadyReleased(id))
        } else {
            Err(CreditError::UnknownClaim(id))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector(memory: u64, handles: u32, processes: u32) -> ResourceVector {
        ResourceVector {
            memory_bytes: memory,
            open_handles: handles,
            ffmpeg_processes: processes,
            ..ResourceVector::default()
        }
    }

    #[test]
    fn atomic_zero_exact_one_over_and_release_identity() -> Result<(), String> {
        let mut ledger = ResourceLedger::new(vector(10, 2, 1), 2, 2, 20);
        let zero = ledger.request(OwnerId(1), vector(0, 0, 0));
        assert!(matches!(zero, Ok(Admission::Granted(_))));
        let exact = ledger.request(OwnerId(2), vector(10, 2, 1));
        let Ok(Admission::Granted(exact)) = exact else {
            return Err("exact capacity must be granted".to_owned());
        };
        assert!(matches!(
            ledger.request(OwnerId(3), vector(11, 0, 0)),
            Err(LedgerError::RequestExceedsCapacity)
        ));
        assert!(matches!(
            ledger.release(exact.id, OwnerId(9)),
            Err(LedgerError::GrantOwnerMismatch { .. })
        ));
        assert!(ledger.release(exact.id, exact.owner).is_ok());
        assert!(matches!(
            ledger.release(exact.id, exact.owner),
            Err(LedgerError::GrantAlreadyReleased(_))
        ));
        assert!(ledger.verify().is_ok());
        Ok(())
    }

    #[test]
    fn checked_vector_never_wraps_or_underflows() {
        assert!(
            vector(u64::MAX, u32::MAX, u32::MAX)
                .checked_add(vector(1, 1, 1))
                .is_none()
        );
        assert!(
            ResourceVector::default()
                .checked_sub(vector(1, 0, 0))
                .is_none()
        );
    }

    #[test]
    fn queue_is_bounded_fifo_and_cancelled_waiters_progress() -> Result<(), String> {
        let mut ledger = ResourceLedger::new(vector(10, 2, 1), 2, 2, 20);
        let first = ledger.request(OwnerId(1), vector(10, 1, 0));
        let Ok(Admission::Granted(first)) = first else {
            return Err("initial grant required".to_owned());
        };
        let large = ledger.request(OwnerId(2), vector(10, 1, 0));
        let Ok(Admission::Queued(large)) = large else {
            return Err("large request must queue".to_owned());
        };
        let small = ledger.request(OwnerId(3), vector(1, 1, 0));
        let Ok(Admission::Queued(small)) = small else {
            return Err("small request must queue behind FIFO head".to_owned());
        };
        assert!(matches!(
            ledger.request(OwnerId(4), vector(1, 0, 0)),
            Err(LedgerError::QueueItemLimit)
        ));
        assert!(ledger.cancel_waiter(large).is_ok());
        let issued = ledger.release(first.id, first.owner);
        let Ok(issued) = issued else {
            return Err("release must dispatch the next waiter".to_owned());
        };
        assert_eq!(issued.len(), 1);
        assert_eq!(issued.first().map(|grant| grant.owner), Some(OwnerId(3)));
        assert!(matches!(
            ledger.cancel_waiter(small),
            Err(LedgerError::UnknownWaiter(_))
        ));
        assert!(ledger.verify().is_ok());
        Ok(())
    }

    #[test]
    fn queue_byte_bound_rejects_saturation_without_mutation() {
        let mut ledger = ResourceLedger::new(vector(10, 1, 0), 2, 4, 5);
        let first = ledger.request(OwnerId(1), vector(10, 0, 0));
        assert!(matches!(first, Ok(Admission::Granted(_))));
        assert!(matches!(
            ledger.request(OwnerId(2), vector(6, 0, 0)),
            Err(LedgerError::QueueByteLimit)
        ));
        assert_eq!(ledger.waiter_occupancy(), (0, 0));
    }

    #[test]
    fn byte_credit_conserves_capacity_and_transfer_identity() -> Result<(), String> {
        let mut credits = ByteCreditLedger::new(10, 2);
        assert!(matches!(
            credits.claim(OwnerId(1), 0),
            Err(CreditError::ZeroClaim)
        ));
        let claim = credits.claim(OwnerId(1), 10);
        let Ok(claim) = claim else {
            return Err("exact byte capacity must be granted".to_owned());
        };
        assert!(matches!(
            credits.claim(OwnerId(2), 1),
            Err(CreditError::CapacityExceeded)
        ));
        assert!(credits.transfer(claim, OwnerId(1), OwnerId(2)).is_ok());
        assert!(matches!(
            credits.release(claim, OwnerId(1)),
            Err(CreditError::ClaimOwnerMismatch)
        ));
        assert!(credits.release(claim, OwnerId(2)).is_ok());
        assert_eq!(credits.in_use(), 0);
        assert!(credits.verify().is_ok());
        assert!(matches!(
            credits.release(claim, OwnerId(2)),
            Err(CreditError::ClaimAlreadyReleased(_))
        ));
        Ok(())
    }

    #[test]
    fn durable_position_is_monotonic_and_never_ahead_of_written() {
        let mut credits = ByteCreditLedger::new(u64::MAX, 1);
        let claim = credits
            .claim(OwnerId(1), u64::MAX)
            .expect("maximum claim must fit");
        assert!(credits.receive(claim, OwnerId(1), u64::MAX).is_ok());
        assert!(
            credits
                .advance(DurabilityPosition {
                    received_bytes: u64::MAX,
                    validated_bytes: u64::MAX - 1,
                    durable_bytes: u64::MAX - 2,
                })
                .is_ok()
        );
        assert!(matches!(
            credits.advance(DurabilityPosition {
                received_bytes: u64::MAX,
                validated_bytes: u64::MAX,
                durable_bytes: u64::MAX,
            }),
            Ok(())
        ));
        assert!(matches!(
            credits.advance(DurabilityPosition {
                received_bytes: u64::MAX,
                validated_bytes: u64::MAX - 1,
                durable_bytes: u64::MAX - 1,
            }),
            Err(CreditError::PositionRegressed)
        ));
        let mut invalid = ByteCreditLedger::new(1, 1);
        let claim = invalid.claim(OwnerId(1), 1).expect("claim must fit");
        assert!(invalid.receive(claim, OwnerId(1), 1).is_ok());
        assert!(matches!(
            invalid.advance(DurabilityPosition {
                received_bytes: 1,
                validated_bytes: 1,
                durable_bytes: 2,
            }),
            Err(CreditError::DurableAheadOfWritten)
        ));
        assert!(matches!(
            invalid.advance(DurabilityPosition {
                received_bytes: 1,
                validated_bytes: 2,
                durable_bytes: 1,
            }),
            Err(CreditError::WrittenAheadOfReceived)
        ));
    }

    #[test]
    fn durability_rejects_bytes_that_were_never_credited() {
        let mut credits = ByteCreditLedger::new(1, 1);
        let claim = credits.claim(OwnerId(1), 1).expect("claim must fit");
        assert!(matches!(
            credits.receive(claim, OwnerId(1), u64::MAX),
            Err(CreditError::UncreditedBytes {
                received: u64::MAX,
                credited: 1
            })
        ));
        assert_eq!(credits.position(), DurabilityPosition::default());
    }

    #[test]
    fn released_unused_credit_cannot_authorize_receive() {
        let mut credits = ByteCreditLedger::new(10, 1);
        let claim = credits.claim(OwnerId(1), 10).expect("claim must fit");
        assert_eq!(
            credits.release(claim, OwnerId(1)),
            Ok(CreditAttribution {
                claim_id: claim,
                owner: OwnerId(1),
                bytes: 10,
                consumed: 0,
            })
        );
        assert!(matches!(
            credits.receive(claim, OwnerId(1), 1),
            Err(CreditError::ClaimAlreadyReleased(id)) if id == claim
        ));
        assert!(credits.verify().is_ok());
    }

    #[test]
    fn consumed_credit_survives_release_but_unused_remainder_does_not() {
        let mut credits = ByteCreditLedger::new(10, 1);
        let claim = credits.claim(OwnerId(1), 10).expect("claim must fit");
        assert!(credits.receive(claim, OwnerId(1), 4).is_ok());
        assert!(
            credits
                .advance(DurabilityPosition {
                    received_bytes: 4,
                    validated_bytes: 4,
                    durable_bytes: 4,
                })
                .is_ok()
        );
        assert_eq!(
            credits.release(claim, OwnerId(1)),
            Ok(CreditAttribution {
                claim_id: claim,
                owner: OwnerId(1),
                bytes: 10,
                consumed: 4,
            })
        );
        assert!(
            credits
                .advance(DurabilityPosition {
                    received_bytes: 4,
                    validated_bytes: 4,
                    durable_bytes: 4,
                })
                .is_ok()
        );
        assert!(matches!(
            credits.advance(DurabilityPosition {
                received_bytes: 5,
                validated_bytes: 4,
                durable_bytes: 4,
            }),
            Err(CreditError::ReceivedBytesRequireClaim)
        ));
        assert!(credits.verify().is_ok());
    }

    #[test]
    fn receive_requires_exact_claim_owner_and_records_attribution() {
        let mut credits = ByteCreditLedger::new(10, 2);
        let first = credits.claim(OwnerId(1), 5).expect("first claim");
        let second = credits.claim(OwnerId(2), 5).expect("second claim");
        let before = credits.clone();
        assert!(matches!(
            credits.receive(first, OwnerId(2), 3),
            Err(CreditError::ClaimOwnerMismatch)
        ));
        assert_eq!(credits, before, "wrong-owner receive must be atomic");
        assert!(credits.receive(second, OwnerId(2), 3).is_ok());
        assert_eq!(
            credits.attribution(first),
            Ok(CreditAttribution {
                claim_id: first,
                owner: OwnerId(1),
                bytes: 5,
                consumed: 0,
            })
        );
        assert_eq!(
            credits.attribution(second),
            Ok(CreditAttribution {
                claim_id: second,
                owner: OwnerId(2),
                bytes: 5,
                consumed: 3,
            })
        );
        assert!(credits.verify().is_ok());
    }

    #[test]
    fn release_is_atomic_when_a_waiter_cannot_fit_at_integer_boundary() -> Result<(), String> {
        let mut ledger = ResourceLedger::new(vector(u64::MAX, 0, 0), 3, 2, u64::MAX);
        let first = ledger.request(OwnerId(1), vector(u64::MAX - 10, 0, 0));
        let Ok(Admission::Granted(_first)) = first else {
            return Err("first boundary grant must be admitted".to_owned());
        };
        let second = ledger.request(OwnerId(2), vector(5, 0, 0));
        let Ok(Admission::Granted(second)) = second else {
            return Err("second boundary grant must be admitted".to_owned());
        };
        assert!(matches!(
            ledger.request(OwnerId(3), vector(20, 0, 0)),
            Ok(Admission::Queued(_))
        ));
        assert!(
            matches!(ledger.release(second.id, second.owner), Ok(ref issued) if issued.is_empty())
        );
        assert_eq!(ledger.in_use(), vector(u64::MAX - 10, 0, 0));
        assert!(ledger.verify().is_ok());
        Ok(())
    }

    #[test]
    fn active_and_claim_item_limits_bound_zero_and_tiny_ownership() {
        let mut ledger = ResourceLedger::new(ResourceVector::default(), 1, 1, 0);
        assert!(matches!(
            ledger.request(OwnerId(1), ResourceVector::default()),
            Ok(Admission::Granted(_))
        ));
        assert!(matches!(
            ledger.request(OwnerId(2), ResourceVector::default()),
            Ok(Admission::Queued(_))
        ));
        assert_eq!(ledger.waiter_occupancy(), (1, 0));

        let mut credits = ByteCreditLedger::new(u64::MAX, 1);
        assert!(credits.claim(OwnerId(1), 1).is_ok());
        assert!(matches!(
            credits.claim(OwnerId(2), 1),
            Err(CreditError::ClaimItemLimit)
        ));
    }

    #[test]
    fn fair_scheduler_preserves_fifo_when_head_becomes_eligible() -> Result<(), String> {
        let mut ledger = ResourceLedger::new(vector(10, 2, 0), 2, 2, 20);
        let first = ledger.request(OwnerId(1), vector(5, 0, 0));
        let Ok(Admission::Granted(first)) = first else {
            return Err("initial grant required".to_owned());
        };
        assert!(matches!(
            ledger.request(OwnerId(2), vector(10, 0, 0)),
            Ok(Admission::Queued(_))
        ));
        assert!(matches!(
            ledger.request(OwnerId(3), vector(1, 0, 0)),
            Ok(Admission::Queued(_))
        ));
        let issued = ledger.release(first.id, first.owner);
        assert!(matches!(
            issued,
            Ok(grants) if grants.first().map(|grant| grant.owner) == Some(OwnerId(2))
        ));
        assert_eq!(ledger.waiter_occupancy(), (1, 1));
        Ok(())
    }

    #[test]
    fn fifo_head_reservation_prevents_large_request_starvation() -> Result<(), String> {
        let mut ledger = ResourceLedger::new(vector(10, 0, 0), 3, 4, 40);
        let six = ledger.request(OwnerId(1), vector(6, 0, 0));
        let Ok(Admission::Granted(six)) = six else {
            return Err("six-unit grant required".to_owned());
        };
        let four = ledger.request(OwnerId(2), vector(4, 0, 0));
        let Ok(Admission::Granted(four)) = four else {
            return Err("four-unit grant required".to_owned());
        };
        assert!(matches!(
            ledger.request(OwnerId(3), vector(10, 0, 0)),
            Ok(Admission::Queued(_))
        ));
        assert!(matches!(
            ledger.request(OwnerId(4), vector(6, 0, 0)),
            Ok(Admission::Queued(_))
        ));

        let first_release = ledger
            .release(six.id, six.owner)
            .map_err(|error| format!("first release failed: {error:?}"))?;
        assert!(
            first_release.is_empty(),
            "later small work may not bypass FIFO head"
        );
        assert_eq!(ledger.in_use(), vector(4, 0, 0));

        let second_release = ledger
            .release(four.id, four.owner)
            .map_err(|error| format!("second release failed: {error:?}"))?;
        assert_eq!(second_release.len(), 1);
        assert_eq!(second_release[0].owner, OwnerId(3));
        assert_eq!(ledger.waiter_occupancy(), (1, 6));
        assert!(ledger.verify().is_ok());
        Ok(())
    }

    #[test]
    fn one_owner_cannot_monopolize_multiple_active_slots() {
        let mut ledger = ResourceLedger::new(vector(10, 0, 0), 2, 2, 20);
        assert!(matches!(
            ledger.request(OwnerId(1), vector(1, 0, 0)),
            Ok(Admission::Granted(_))
        ));
        let same_owner = ledger.request(OwnerId(1), vector(1, 0, 0));
        let Ok(Admission::Queued(same_owner)) = same_owner else {
            return assert!(matches!(same_owner, Ok(Admission::Queued(_))));
        };
        assert!(matches!(
            ledger.request(OwnerId(2), vector(1, 0, 0)),
            Ok(Admission::Queued(_))
        ));
        assert!(matches!(
            ledger.cancel_waiter(same_owner),
            Ok(grants) if grants.first().map(|grant| grant.owner) == Some(OwnerId(2))
        ));
    }

    #[test]
    fn cancelling_fifo_head_immediately_dispatches_unblocked_waiter() {
        let mut ledger = ResourceLedger::new(vector(10, 2, 0), 2, 2, 20);
        let first = ledger.request(OwnerId(1), vector(5, 0, 0));
        let Ok(Admission::Granted(_first)) = first else {
            return assert!(matches!(first, Ok(Admission::Granted(_))));
        };
        let head = ledger.request(OwnerId(2), vector(10, 0, 0));
        let Ok(Admission::Queued(head)) = head else {
            return assert!(matches!(head, Ok(Admission::Queued(_))));
        };
        assert!(matches!(
            ledger.request(OwnerId(3), vector(5, 0, 0)),
            Ok(Admission::Queued(_))
        ));
        let dispatched = ledger.cancel_waiter(head);
        assert!(matches!(
            dispatched,
            Ok(grants) if grants.first().map(|grant| grant.owner) == Some(OwnerId(3))
        ));
        assert_eq!(ledger.waiter_occupancy(), (0, 0));
        assert!(ledger.verify().is_ok());
    }
}
