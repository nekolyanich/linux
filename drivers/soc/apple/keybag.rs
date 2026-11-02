// SPDX-License-Identifier: GPL-2.0-only OR MIT
// Copyright 2026 Dj

//! Host-side persistence for the key bag.
//!
//! `0x02` copies the bag out enclave-wrapped, `0x03` reloads it. NEVER create a
//! second bag while a stored blob exists — it orphans the previous one in the
//! enclave with no recovery; [`NoStoredKeyBag`] enforces this by type.
//!
//! The identity bag is uid 1000's home bag, kept like every uid's (tanabota,
//! 2026-11-01): its record is `/var/lib/tanabota-sep-bag-1000.bin` in
//! userbag.rs's format (H, with its home flag). The old record
//! `aurora-sep-keybag.bin` (K) stays as a mirror in this format, rewritten
//! with H, so a rollback generation reads the same bag and secret and never
//! provisions a new one over it (with K missing, an old kernel's
//! `provision_keybag=1` would create a new identity bag); R3 removes it.
//! The create's intent and refusal markers stay in K.
//!
//! In password mode (R2) H stores no secret, and K must not either: K is then
//! the create's intent marker. An old generation reads that as "a bag may
//! exist unnamed" (EEXIST): it never provisions over it, and has no identity
//! bag (no Touch ID, no keys in it) until rolled forward. Back to a stored
//! secret, K is the mirror again.
//!
//! Migration, at every read of the slot, idempotent, each step one atomic
//! replace or a create that never overwrites:
//! 1. H holds uid 1000's own bag from before (no home flag): copied to
//!    `tanabota-sep-bag-1000.legacy.bin` (the -7 retry reads it there); an
//!    identical copy already there is a crash between this and step 2.
//! 2. K committed and H not home: H written from K (same bag, uuid, secret,
//!    provenance) and read back to compare.
//! 3. H home and K differs: the same uuid and secret with another wrapped
//!    copy is a snapshot only K got (an older generation writes K alone, and
//!    a snapshot writes K before H): H takes K's copy. Anything else (another
//!    secret: a change whose mirror write was lost; K missing, an intent or
//!    unreadable) is H's: K is rewritten from H. A change writes H before K,
//!    so a stale K never wins, and an old K left after a secret change would
//!    be an open copy (no generation in the enclave), so it never stays.

use crate::shim;
use crate::store::crc16_ccitt_false;
use kernel::prelude::*;

pub(crate) const KEYBAG_PATH: &CStr = c"/var/lib/aurora-sep-keybag.bin";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    Identity,
}

impl Slot {
    pub(crate) fn path(self) -> &'static CStr {
        match self {
            Slot::Identity => KEYBAG_PATH,
        }
    }
}

const MAGIC: [u8; 16] = *b"APPLE-SEP-KBAG01";
/// v2 stores the bag secret; a v1 record is refused, not reinterpreted.
const VERSION: u32 = 2;

const STATE_COMMITTED: u32 = 1;
/// Create refused by the enclave: nothing exists, retry allowed (unlike an
/// intent record, where a bag may exist unnamed — block retry).
const STATE_REFUSED: u32 = 2;
/// UUID field is the bag's own, read back via `0x06`; state 1 holds the
/// host-generated one, and for an identity bag these differ.
const STATE_COMMITTED_BAG_UUID: u32 = 3;

/// Only an `AsGenerated` UUID may be repaired on a mismatch; adopting one for a
/// read-back record would point it at a different bag and strand the real one.
pub(crate) use crate::keybag_identity::{SnapshotIdentity, UuidProvenance};

impl UuidProvenance {
    fn state(self) -> u32 {
        match self {
            Self::AsGenerated => STATE_COMMITTED,
            Self::ReadBackFromBag => STATE_COMMITTED_BAG_UUID,
        }
    }

    fn from_state(state: u32) -> Option<Self> {
        match state {
            STATE_COMMITTED => Some(Self::AsGenerated),
            STATE_COMMITTED_BAG_UUID => Some(Self::ReadBackFromBag),
            _ => None,
        }
    }
}

const OFF_VERSION: usize = 0x10;
const OFF_STATE: usize = 0x14;
const OFF_LEN: usize = 0x18;
const OFF_CRC: usize = 0x1c;
const OFF_UUID: usize = 0x20;
const OFF_SECRET_LEN: usize = 0x30;
const HEADER: usize = 0x34;

static_assert!(OFF_VERSION == MAGIC.len());
static_assert!(OFF_STATE == OFF_VERSION + 4);
static_assert!(OFF_LEN == OFF_STATE + 4);
static_assert!(OFF_CRC == OFF_LEN + 4);
static_assert!(OFF_UUID == OFF_CRC + 4);
static_assert!(OFF_SECRET_LEN == OFF_UUID + UUID_LEN);
static_assert!(HEADER == OFF_SECRET_LEN + 4);

pub(crate) const UUID_LEN: usize = 16;

const MAX_WRAPPED: usize = crate::store::MAX_VALUE;

/// Proof the host holds no bag; create takes one by value, so it is unreachable
/// without it and unrepeatable with it.
pub(crate) struct NoStoredKeyBag {
    slot: Slot,
}

impl NoStoredKeyBag {
    pub(crate) fn slot(&self) -> Slot {
        self.slot
    }
}

pub(crate) struct StoredKeyBag {
    wrapped: KVec<u8>,
    uuid: [u8; UUID_LEN],
    secret: crate::Secret,
    provenance: UuidProvenance,
    /// userbag's FLAG_PASSWORD / FLAG_LOGIN_SAME of uid 1000's home record.
    mode: u16,
}

impl StoredKeyBag {
    pub(crate) fn wrapped(&self) -> &[u8] {
        &self.wrapped
    }

    pub(crate) fn uuid(&self) -> &[u8; UUID_LEN] {
        &self.uuid
    }

    pub(crate) fn uuid_provenance(&self) -> UuidProvenance {
        self.provenance
    }

    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Password mode: the record holds no secret; [`Self::with_secret`]
    /// gives the one SEP_KEY_UNLOCK brought.
    pub(crate) fn password(&self) -> bool {
        self.mode & crate::userbag::FLAG_PASSWORD != 0
    }

    pub(crate) fn with_secret(mut self, secret: crate::Secret) -> StoredKeyBag {
        self.secret = secret;
        self
    }
}

pub(crate) enum State {
    Present(StoredKeyBag),
    Absent(NoStoredKeyBag),
}

/// CRC preimage; this byte order is the on-disk contract — changing it breaks
/// records written by an earlier build.
fn checksum_input(
    state: u32,
    wrapped: &[u8],
    uuid: &[u8; UUID_LEN],
    secret: &[u8],
) -> Result<crate::Secret> {
    let mut v = KVec::new();
    v.extend_from_slice(&VERSION.to_le_bytes(), GFP_KERNEL)?;
    v.extend_from_slice(&state.to_le_bytes(), GFP_KERNEL)?;
    v.extend_from_slice(&(wrapped.len() as u32).to_le_bytes(), GFP_KERNEL)?;
    v.extend_from_slice(&(secret.len() as u32).to_le_bytes(), GFP_KERNEL)?;
    v.extend_from_slice(uuid, GFP_KERNEL)?;
    v.extend_from_slice(wrapped, GFP_KERNEL)?;
    v.extend_from_slice(secret, GFP_KERNEL)?;
    Ok(crate::Secret(v))
}

/// Absent only when the file is missing; every other unreadable state errors —
/// "cannot tell" must never read as "nothing here", which would orphan a bag.
pub(crate) fn read(slot: Slot) -> Result<State> {
    migrate(slot)?;
    match crate::userbag::read_home(HOME_UID)? {
        crate::userbag::HomeFile::Home(h) => Ok(State::Present(from_home(h))),
        _ => match read_old(slot)? {
            // migrate() writes H from a committed K or fails
            State::Present(_) => Err(EIO),
            absent => Ok(absent),
        },
    }
}

/// The fingers' user, whose home bag the identity slot is.
const HOME_UID: u32 = crate::SBIO_PROBE_USER_ID as u32;

fn from_home(h: crate::userbag::HomeRecord) -> StoredKeyBag {
    StoredKeyBag {
        wrapped: h.wrapped,
        uuid: h.uuid,
        secret: h.secret,
        provenance: if h.readback { UuidProvenance::ReadBackFromBag } else { UuidProvenance::AsGenerated },
        mode: h.mode,
    }
}

fn readback(p: UuidProvenance) -> bool {
    p == UuidProvenance::ReadBackFromBag
}

/// Brings the files to the module comment's shape; see the steps there.
fn migrate(slot: Slot) -> Result<()> {
    use crate::userbag::{self, HomeFile};
    // a BAG_USE cut short leaves a retired copy of the home bag: removed
    let _ = userbag::tidy(HOME_UID);
    let home = userbag::read_home(HOME_UID)?;
    if matches!(home, HomeFile::Legacy) {
        userbag::move_legacy_aside(HOME_UID)?;
    }
    let old = read_old(slot);
    match (home, old) {
        // password mode: K is the intent marker, never a secret
        (HomeFile::Home(h), old) if h.mode & userbag::FLAG_PASSWORD != 0 => match old {
            Err(e) if e == EEXIST => Ok(()),
            _ => write_intent(slot),
        },
        (HomeFile::Home(h), Ok(State::Present(k))) => {
            if k.uuid == h.uuid && k.provenance == readback_of(h.readback) && *k.secret == *h.secret {
                if k.wrapped != h.wrapped {
                    pr_info!("apple_sep: uid 1000's home record takes the identity record's newer snapshot\n");
                    userbag::write_home(HOME_UID, &h.uuid, h.readback, h.mode, &h.secret, &k.wrapped)?;
                }
                Ok(())
            } else {
                pr_warn!("apple_sep: the identity record differs from uid 1000's home record: rewritten from it\n");
                write_record(slot, readback_of(h.readback).state(), &h.wrapped, &h.uuid, &h.secret)
            }
        }
        (HomeFile::Home(h), _) => {
            write_record(slot, readback_of(h.readback).state(), &h.wrapped, &h.uuid, &h.secret)
        }
        (_, Ok(State::Present(k))) => {
            userbag::write_home(HOME_UID, &k.uuid, readback(k.provenance), 0, &k.secret, &k.wrapped)?;
            match userbag::read_home(HOME_UID)? {
                HomeFile::Home(h) if h.uuid == k.uuid && h.wrapped == k.wrapped && *h.secret == *k.secret => {
                    pr_info!("apple_sep: the identity bag's record moved to uid 1000's home record\n");
                    Ok(())
                }
                _ => Err(EIO),
            }
        }
        (_, _) => Ok(()),
    }
}

fn readback_of(readback: bool) -> UuidProvenance {
    if readback { UuidProvenance::ReadBackFromBag } else { UuidProvenance::AsGenerated }
}

/// K as the record it is (intent, refused, committed).
fn read_old(slot: Slot) -> Result<State> {
    let file = match shim::StoreFile::open_readonly(slot.path()) {
        Ok(f) => f,
        Err(e) if e == ENOENT => {
            return Ok(State::Absent(NoStoredKeyBag { slot }));
        }
        Err(e) => return Err(e),
    };

    let size = file.size()?;
    if size < HEADER as u64 {
        return Err(EINVAL);
    }

    let mut head = [0u8; HEADER];
    file.read_exact(0, &mut head)?;
    if head[..MAGIC.len()] != MAGIC {
        return Err(EINVAL);
    }
    let version = u32::from_le_bytes([
        head[OFF_VERSION],
        head[OFF_VERSION + 1],
        head[OFF_VERSION + 2],
        head[OFF_VERSION + 3],
    ]);
    if version != VERSION {
        return Err(ENOTSYNC);
    }
    let state = u32::from_le_bytes([
        head[OFF_STATE],
        head[OFF_STATE + 1],
        head[OFF_STATE + 2],
        head[OFF_STATE + 3],
    ]);
    if state == STATE_REFUSED {
        return Ok(State::Absent(NoStoredKeyBag { slot }));
    }
    let Some(provenance) = UuidProvenance::from_state(state) else {
        // Intent or unknown state: a bag may exist unnamed; creating again would
        // orphan it permanently.
        return Err(EEXIST);
    };

    let len = u32::from_le_bytes([
        head[OFF_LEN],
        head[OFF_LEN + 1],
        head[OFF_LEN + 2],
        head[OFF_LEN + 3],
    ]) as usize;
    if len == 0 || len > MAX_WRAPPED || size < (HEADER + len) as u64 {
        return Err(EINVAL);
    }
    let crc = u16::from_le_bytes([head[OFF_CRC], head[OFF_CRC + 1]]);

    let mut uuid = [0u8; UUID_LEN];
    uuid.copy_from_slice(&head[OFF_UUID..OFF_UUID + UUID_LEN]);

    let secret_len = u32::from_le_bytes([
        head[OFF_SECRET_LEN],
        head[OFF_SECRET_LEN + 1],
        head[OFF_SECRET_LEN + 2],
        head[OFF_SECRET_LEN + 3],
    ]) as usize;
    if secret_len > MAX_WRAPPED || size < (HEADER + len + secret_len) as u64 {
        return Err(EINVAL);
    }

    let mut wrapped = KVec::with_capacity(len, GFP_KERNEL)?;
    wrapped.resize(len, 0, GFP_KERNEL)?;
    file.read_exact(HEADER as u64, &mut wrapped)?;

    let mut secret_bytes = KVec::with_capacity(secret_len, GFP_KERNEL)?;
    secret_bytes.resize(secret_len, 0, GFP_KERNEL)?;
    if secret_len > 0 {
        file.read_exact((HEADER + len) as u64, &mut secret_bytes)?;
    }

    if size != (HEADER + len + secret_len) as u64 {
        return Err(EINVAL);
    }
    let secret = crate::Secret(secret_bytes);

    if crc16_ccitt_false(&checksum_input(state, &wrapped, &uuid, &secret)?) != crc {
        return Err(EINVAL);
    }

    Ok(State::Present(StoredKeyBag {
        wrapped,
        uuid,
        secret,
        provenance,
        mode: 0,
    }))
}

pub(crate) fn write_intent(slot: Slot) -> Result<()> {
    write_record(slot, 0, &[], &[0; UUID_LEN], &[])
}

pub(crate) fn mark_refused(slot: Slot) -> Result<()> {
    write_record(slot, STATE_REFUSED, &[], &[0; UUID_LEN], &[])
}

pub(crate) fn write_bag_uuid(
    slot: Slot,
    wrapped: &[u8],
    uuid: &[u8; UUID_LEN],
    secret: &[u8],
) -> Result<()> {
    if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED || secret.len() > MAX_WRAPPED {
        return Err(EINVAL);
    }
    // a create: H first; a crash before K leaves K's intent, which the next
    // read rewrites from H
    crate::userbag::write_home(HOME_UID, uuid, true, 0, secret, wrapped)?;
    write_record(
        slot,
        UuidProvenance::ReadBackFromBag.state(),
        wrapped,
        uuid,
        secret,
    )
}

/// Commits a bag named by the host-generated UUID it was created with: the
/// 13.5 enclave keeps an identity bag itself and loads it by that UUID.
pub(crate) fn write_generated_uuid(
    slot: Slot,
    wrapped: &[u8],
    uuid: &[u8; UUID_LEN],
    secret: &[u8],
) -> Result<()> {
    if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED || secret.len() > MAX_WRAPPED {
        return Err(EINVAL);
    }
    crate::userbag::write_home(HOME_UID, uuid, false, 0, secret, wrapped)?;
    write_record(
        slot,
        UuidProvenance::AsGenerated.state(),
        wrapped,
        uuid,
        secret,
    )
}

/// Replaces only the wrapped blob. The enclave ratchets bag material while a bag
/// is active, so this snapshot must be re-taken at the catacomb-save commit or
/// the enclave answers a later restore empty.
pub(crate) fn replace_wrapped(
    slot: Slot,
    fresh: &[u8],
    snapshot_uuid: &[u8; UUID_LEN],
    identity: &SnapshotIdentity,
) -> Result<()> {
    if fresh.is_empty() || fresh.len() > MAX_WRAPPED {
        return Err(EINVAL);
    }
    let stored = match read(slot)? {
        State::Present(stored) => stored,
        State::Absent(_) => return Err(ENOENT),
    };
    if !identity.accepts(stored.uuid(), stored.uuid_provenance(), snapshot_uuid) {
        // Reject a different bag or changed host identity. The generated
        // Sepos13 lookup UUID is not the UUID returned by COPY_KEYBAG_UUID.
        return Err(EPERM);
    }
    // a snapshot: K first, then H; a crash between leaves K's newer copy with
    // the same secret, which the next read gives H. In password mode K stays
    // the marker and H alone takes the copy.
    if !stored.password() {
        write_record(
            slot,
            stored.uuid_provenance().state(),
            fresh,
            stored.uuid(),
            stored.secret(),
        )?;
    }
    crate::userbag::write_home(HOME_UID, stored.uuid(), readback(stored.provenance), stored.mode, stored.secret(), fresh)
}

/// Replaces the wrapped blob and the secret together, after the enclave
/// changed the bag's secret: the same bag (uuid, provenance), one atomic
/// replace. The previous record still opens with the previous secret (the
/// enclave keeps no generation, tanabota U-J): the caller must not leave it
/// anywhere else.
/// `mode`: userbag's FLAG_PASSWORD / FLAG_LOGIN_SAME of the bag after the
/// change; with a password, H stores no secret and K becomes the marker.
pub(crate) fn replace_bag_and_secret(slot: Slot, fresh: &[u8], secret: &[u8], mode: u16) -> Result<()> {
    if fresh.is_empty() || fresh.len() > MAX_WRAPPED || secret.is_empty() || secret.len() > MAX_WRAPPED {
        return Err(EINVAL);
    }
    let stored = match read(slot)? {
        State::Present(stored) => stored,
        State::Absent(_) => return Err(ENOENT),
    };
    // a change: H first, then K; a crash between leaves K with the old
    // secret, which the next read rewrites from H
    crate::userbag::write_home(HOME_UID, stored.uuid(), readback(stored.provenance), mode, secret, fresh)?;
    if mode & crate::userbag::FLAG_PASSWORD != 0 {
        return write_intent(slot);
    }
    write_record(slot, stored.uuid_provenance().state(), fresh, stored.uuid(), secret)
}

fn write_record(
    slot: Slot,
    state: u32,
    wrapped: &[u8],
    uuid: &[u8; UUID_LEN],
    secret: &[u8],
) -> Result<()> {
    let crc = crc16_ccitt_false(&checksum_input(state, wrapped, uuid, secret)?);

    let mut head = [0u8; HEADER];
    head[..MAGIC.len()].copy_from_slice(&MAGIC);
    head[OFF_VERSION..OFF_VERSION + 4].copy_from_slice(&VERSION.to_le_bytes());
    head[OFF_STATE..OFF_STATE + 4].copy_from_slice(&state.to_le_bytes());
    head[OFF_LEN..OFF_LEN + 4].copy_from_slice(&(wrapped.len() as u32).to_le_bytes());
    head[OFF_CRC..OFF_CRC + 2].copy_from_slice(&crc.to_le_bytes());
    head[OFF_UUID..OFF_UUID + UUID_LEN].copy_from_slice(uuid);
    head[OFF_SECRET_LEN..OFF_SECRET_LEN + 4].copy_from_slice(&(secret.len() as u32).to_le_bytes());

    // The whole record goes in one atomic replace: a crash keeps the previous
    // record or leaves the new one, so the only copy is never torn.
    let mut rec = crate::Secret(KVec::new());
    rec.0
        .reserve(HEADER + wrapped.len() + secret.len(), GFP_KERNEL)?;
    rec.0.extend_from_slice(&head, GFP_KERNEL)?;
    rec.0.extend_from_slice(wrapped, GFP_KERNEL)?;
    rec.0.extend_from_slice(secret, GFP_KERNEL)?;
    shim::replace_file(slot.path(), &rec)
}
