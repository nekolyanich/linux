// SPDX-License-Identifier: GPL-2.0-only OR MIT
// Copyright 2026 Dj

//! Device-wide xART gigalocker record store.
//!
//! The APFS locator identifies the existing `.gl` file's physical extent.
//! This module validates records and serves SEP reads from that extent. It
//! never creates storage. Writes are opt-in and require narrow APFS checks
//! for an unshared, unsnapshotted extent.

use crate::shim;
use kernel::prelude::*;

/// The raw-extent owner opens this whole partition (the iBoot system container,
/// where the gigalocker lives) and serves the gigalocker window directly.
pub(crate) const OWNER_PATH: &CStr = c"/dev/disk/by-partlabel/iBootSystemContainer";
/// Its GPT name, for when the link is missing.
pub(crate) const OWNER_LABEL: &CStr = c"iBootSystemContainer";

const BLOCK_SIZE: usize = 0x1000;
const SLOT_SIZE: usize = 0x9000;
const HEADER_SIZE: usize = 0x22;
const DELETE_SIZE: usize = BLOCK_SIZE;
/// The current `.gl` format occupies one contiguous six-MiB APFS file extent.
/// Unsupported layouts fail closed in `xart_apfs::locate`.
const STORE_SIZE: u64 = 0x600000;
const MAX_SLOTS: usize = 4096;

pub(crate) const MAX_VALUE: usize = 0x8000;

const KEY_KIND: usize = 0x01;
const KEY_UUID: usize = 0x02;
const LENGTH: usize = 0x12;
const CRC: usize = 0x16;
const REVISION: usize = 0x1a;
const PAYLOAD: usize = HEADER_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Key {
    pub(crate) kind: u8,
    pub(crate) uuid: [u8; 16],
}

impl Key {
    pub(crate) const fn new(kind: u8, uuid: [u8; 16]) -> Key {
        Key { kind, uuid }
    }

    pub(crate) const fn root(kind: u8) -> Key {
        Key {
            kind,
            uuid: [0; 16],
        }
    }
}

#[derive(Clone, Copy)]
struct Slot {
    used: bool,
    key: Key,
    len: u32,
    crc: u32,
    revision: u64,
}

impl Slot {
    const FREE: Slot = Slot {
        used: false,
        key: Key::root(0),
        len: 0,
        crc: 0,
        revision: 0,
    };

    fn matches(&self, key: &Key) -> bool {
        self.used && self.key == *key
    }
}

/// What a scan of the store found, for the probe log.
pub(crate) struct Summary {
    pub(crate) slots: usize,
    pub(crate) records: usize,
    pub(crate) revision: u64,
    pub(crate) malformed: usize,
    pub(crate) unbacked: usize,
    pub(crate) foreign: usize,
    pub(crate) duplicates: usize,
    pub(crate) conflicting: usize,
    pub(crate) repaired: usize,
    pub(crate) writable: bool,
}

pub(crate) struct Store {
    file: shim::StoreFile,
    /// Byte offset of the APFS-resolved gigalocker extent in the container.
    base: u64,
    slots: KVec<Slot>,
    revision: u64,
    writes_enabled: bool,
    valid_records: usize,
    malformed_records: usize,
    /// Records under a key this driver does not know: someone else's (a newer
    /// macOS, another format), never written over or beside.
    foreign_records: usize,
    /// Malformed records with no valid copy of their key, or with a length no
    /// record of ours has: maybe the only copy of something, so never cleared,
    /// and the store stays read-only.
    unbacked_records: usize,
    duplicate_records: usize,
    /// Duplicates at one revision with different contents: no record can be
    /// called the newer, so the store stays read-only.
    conflicting_records: usize,
    repaired_records: usize,
    /// Set with `xart_guard`: refuses writes to records Linux did not create.
    guard: Option<crate::xart_guard::Guard>,
}

fn le32(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

fn le64(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
        bytes[off + 5],
        bytes[off + 6],
        bytes[off + 7],
    ])
}

fn valid_key(key: &Key) -> bool {
    (1..=4).contains(&key.kind) && (key.kind > 2 || key.uuid == [0; 16])
}

impl Store {
    /// Opens the iBoot system container, resolves `.gl` through APFS
    /// metadata, then validates the record store at exactly that extent.
    /// A nonzero start sector is an assertion against the APFS result, never
    /// an override of it. Writes additionally require a single-owner extent
    /// with no snapshots or pending revert, checked on the same block handle.
    pub(crate) fn open_owner(writes_enabled: bool, start_sector: u64) -> Result<Store> {
        // No link without udev (the bench's initrd): the same partition by its GPT name
        let file = match shim::StoreFile::open_block(OWNER_PATH, writes_enabled) {
            Err(e) if e == ENOENT => shim::StoreFile::open_partlabel(OWNER_LABEL, writes_enabled)?,
            r => r?,
        };
        let base = crate::xart_apfs::locate(&file, writes_enabled)?;
        if start_sector != 0 {
            if start_sector.checked_mul(512).ok_or(EINVAL)? != base {
                return Err(EINVAL);
            }
        }
        Self::open_file(file, writes_enabled, base)
    }

    /// Opens a caller-selected block mapping at offset zero.
    ///
    /// The separate xART self-test module uses this entry point with its fixed
    /// loop-only mapper name, so it can execute the real parser and write
    /// ordering without enabling SEP.
    #[allow(dead_code)]
    pub(crate) fn open_at(path: &CStr, writes_enabled: bool) -> Result<Store> {
        Self::open_based(path, writes_enabled, 0)
    }

    /// Opens `path` and serves the [`STORE_SIZE`] window starting at byte
    /// `base`. The window must be block-aligned and fit within the device; the
    /// logical store is always exactly [`STORE_SIZE`], so a larger backing
    /// device (the raw container) serves only its gigalocker extent.
    ///
    /// The block handle's writability equals `writes_enabled`, and repair runs
    /// when writes are enabled. The APFS owner is always read-only.
    fn open_based(path: &CStr, writes_enabled: bool, base: u64) -> Result<Store> {
        let file = shim::StoreFile::open_block(path, writes_enabled)?;
        Self::open_file(file, writes_enabled, base)
    }

    /// Complete record validation using the same handle with which APFS
    /// ownership was resolved, avoiding a close/reopen window.
    fn open_file(file: shim::StoreFile, arm_writes: bool, base: u64) -> Result<Store> {
        let size = file.size()?;
        if base % BLOCK_SIZE as u64 != 0 || STORE_SIZE % BLOCK_SIZE as u64 != 0 {
            return Err(EINVAL);
        }
        let end = base.checked_add(STORE_SIZE).ok_or(EINVAL)?;
        if end > size {
            return Err(EINVAL);
        }
        let count = (STORE_SIZE / SLOT_SIZE as u64) as usize;
        if count == 0 || count > MAX_SLOTS {
            return Err(EINVAL);
        }

        let mut slots = KVec::with_capacity(count, GFP_KERNEL)?;
        for _ in 0..count {
            slots.push(Slot::FREE, GFP_KERNEL)?;
        }
        let mut store = Store {
            file,
            base,
            slots,
            revision: 0,
            // Discovery is always read-only. Do not arm even repair writes
            // until the required root records have validated.
            writes_enabled: false,
            valid_records: 0,
            malformed_records: 0,
            foreign_records: 0,
            unbacked_records: 0,
            duplicate_records: 0,
            conflicting_records: 0,
            repaired_records: 0,
            guard: None,
        };
        store.scan()?;
        // Serving an empty or unrelated 6 MiB mapping is the failure mode that
        // originally desynchronised SEP's anti-replay state. This Linux driver is never
        // the authority that provisions a blank device-wide store. Require
        // both existing root families before any mailbox registration can run.
        if store.find(&Key::root(1)).is_none() || store.find(&Key::root(2)).is_none() {
            return Err(ENODATA);
        }
        // A foreign record, a malformed one with no valid copy, or two
        // different records at one revision keep the store read-only: their
        // slots read as free, and a write could land on them. Reads are still
        // served.
        store.writes_enabled = arm_writes
            && store.foreign_records == 0
            && store.unbacked_records == 0
            && store.conflicting_records == 0;
        // A torn slot whose key has a valid copy (an interrupted replacement)
        // and the losers of a revision-resolved duplicate are what an
        // interrupted write leaves: clear them. A repair that fails leaves the
        // store read-only.
        if store.writes_enabled
            && (store.malformed_records != 0 || store.duplicate_records != 0)
            && store.repair_disk().is_err()
        {
            store.writes_enabled = false;
        }
        Ok(store)
    }

    fn slot_offset(slot: usize) -> u64 {
        (slot * SLOT_SIZE) as u64
    }

    fn scan(&mut self) -> Result<()> {
        let mut raw = KVec::with_capacity(SLOT_SIZE, GFP_KERNEL)?;
        raw.resize(SLOT_SIZE, 0, GFP_KERNEL)?;
        let mut malformed: KVec<Key> = KVec::new();

        for idx in 0..self.slots.len() {
            self.file
                .read_block_exact(self.base + Self::slot_offset(idx), &mut raw)?;
            let kind = raw[KEY_KIND];
            if kind == 0 {
                continue;
            }

            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&raw[KEY_UUID..KEY_UUID + 16]);
            let key = Key { kind, uuid };
            let len = le32(&raw, LENGTH) as usize;
            let crc = le32(&raw, CRC);
            let revision = le64(&raw, REVISION);
            if !valid_key(&key) {
                self.foreign_records += 1;
                continue;
            }
            if !(1..=MAX_VALUE).contains(&len) {
                // Not a torn write of ours (we never write such a length), and
                // maybe a record this driver cannot read: never cleared.
                self.malformed_records += 1;
                self.unbacked_records += 1;
                continue;
            }
            if crc32_ieee(&raw[PAYLOAD..PAYLOAD + len]) != crc {
                self.malformed_records += 1;
                malformed.push(key, GFP_KERNEL)?;
                continue;
            }

            self.revision = self.revision.max(revision);
            let candidate = Slot {
                used: true,
                key,
                len: len as u32,
                crc,
                revision,
            };

            if let Some(old) = self.find(&key) {
                self.duplicate_records += 1;
                let o = self.slots[old];
                if revision == o.revision && (len as u32 != o.len || crc != o.crc) {
                    self.conflicting_records += 1;
                }
                // Equal revisions keep the later physical slot: the forward
                // scan resolves a tie to the last writer.
                if revision >= self.slots[old].revision {
                    self.slots[old] = Slot::FREE;
                    self.slots[idx] = candidate;
                }
            } else {
                self.slots[idx] = candidate;
            }
        }

        self.unbacked_records += malformed.iter().filter(|k| self.find(k).is_none()).count();
        self.valid_records = self.slots.iter().filter(|slot| slot.used).count();
        Ok(())
    }

    /// Removes malformed records and duplicate losers only after the mapping
    /// has passed its complete read-only scan and both root records exist.
    /// Only a slot under a known key with a valid copy elsewhere is cleared;
    /// every write stays inside the validated extent (`slot < slots.len()`).
    fn repair_disk(&mut self) -> Result<()> {
        let mut header = KVec::with_capacity(DELETE_SIZE, GFP_KERNEL)?;
        header.resize(DELETE_SIZE, 0, GFP_KERNEL)?;

        for idx in 0..self.slots.len() {
            if self.slots[idx].used {
                continue;
            }
            self.file
                .read_block_exact(self.base + Self::slot_offset(idx), &mut header)?;
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&header[KEY_UUID..KEY_UUID + 16]);
            let key = Key {
                kind: header[KEY_KIND],
                uuid,
            };
            if key.kind != 0 && valid_key(&key) && self.find(&key).is_some() {
                self.delete_slot(idx)?;
                self.repaired_records += 1;
            }
        }
        Ok(())
    }

    fn find(&self, key: &Key) -> Option<usize> {
        let mut best: Option<usize> = None;
        for (idx, slot) in self.slots.iter().enumerate() {
            if !slot.matches(key) {
                continue;
            }
            if best.is_none_or(|old| slot.revision >= self.slots[old].revision) {
                best = Some(idx);
            }
        }
        best
    }

    fn find_free(&self, skip: usize) -> Option<usize> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| !slot.used)
            .nth(skip)
            .map(|(idx, _)| idx)
    }

    fn delete_slot(&self, slot: usize) -> Result<()> {
        let mut zero = KVec::with_capacity(DELETE_SIZE, GFP_KERNEL)?;
        zero.resize(DELETE_SIZE, 0, GFP_KERNEL)?;
        self.file
            .write_block_exact(self.base + Self::slot_offset(slot), &zero)?;
        self.file.sync()
    }

    pub(crate) fn read(&mut self, key: &Key) -> Result<Option<KVec<u8>>> {
        if !valid_key(key) {
            return Err(EINVAL);
        }
        let Some(idx) = self.find(key) else {
            return Ok(None);
        };
        let slot = self.slots[idx];
        let mut raw = KVec::with_capacity(SLOT_SIZE, GFP_KERNEL)?;
        raw.resize(SLOT_SIZE, 0, GFP_KERNEL)?;
        self.file
            .read_block_exact(self.base + Self::slot_offset(idx), &mut raw)?;

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&raw[KEY_UUID..KEY_UUID + 16]);
        let disk_key = Key {
            kind: raw[KEY_KIND],
            uuid,
        };
        let len = le32(&raw, LENGTH) as usize;
        if disk_key != *key
            || len != slot.len as usize
            || le32(&raw, CRC) != slot.crc
            || le64(&raw, REVISION) != slot.revision
            || crc32_ieee(&raw[PAYLOAD..PAYLOAD + len]) != slot.crc
        {
            return Err(EIO);
        }

        let mut value = KVec::with_capacity(len, GFP_KERNEL)?;
        value.extend_from_slice(&raw[PAYLOAD..PAYLOAD + len], GFP_KERNEL)?;
        Ok(Some(value))
    }

    pub(crate) fn write(&mut self, key: &Key, value: &[u8]) -> Result<()> {
        if !self.writes_enabled {
            return Err(EROFS);
        }
        if !valid_key(key) || value.is_empty() || value.len() > MAX_VALUE {
            return Err(EINVAL);
        }

        if let Some(guard) = self.guard.as_mut() {
            guard.check(key, true)?;
        }

        let old = self.find(key);
        // A new key skips the first free slot; a replacement reuses it.
        let fresh = self.find_free(usize::from(old.is_none())).ok_or(ENOSPC)?;
        let revision = self.revision.checked_add(1).ok_or(EINVAL)?;
        let crc = crc32_ieee(value);

        let mut raw = KVec::with_capacity(SLOT_SIZE, GFP_KERNEL)?;
        raw.resize(SLOT_SIZE, 0, GFP_KERNEL)?;
        raw[KEY_KIND] = key.kind;
        raw[KEY_UUID..KEY_UUID + 16].copy_from_slice(&key.uuid);
        raw[LENGTH..LENGTH + 4].copy_from_slice(&(value.len() as u32).to_le_bytes());
        raw[CRC..CRC + 4].copy_from_slice(&crc.to_le_bytes());
        raw[REVISION..REVISION + 8].copy_from_slice(&revision.to_le_bytes());
        raw[PAYLOAD..PAYLOAD + value.len()].copy_from_slice(value);

        // The new record becomes authoritative only after its complete slot is
        // durable.  The old record is then removed and flushed separately.
        self.file
            .write_block_exact(self.base + Self::slot_offset(fresh), &raw)?;
        self.file.sync()?;
        self.slots[fresh] = Slot {
            used: true,
            key: *key,
            len: value.len() as u32,
            crc,
            revision,
        };
        self.revision = revision;

        if let Some(old) = old {
            // The new record is durable and wins on revision, so the write has
            // happened: failing it now would tell the enclave its state was not
            // saved when it was. An old slot that cannot be cleared stays a
            // shadowed duplicate on disk, for the next repair, and in use here
            // so that no write lands on it.
            match self.delete_slot(old) {
                Ok(()) => self.slots[old] = Slot::FREE,
                Err(e) => pr_warn!(
                    "apple-sep: xART: clearing the replaced slot {} failed ({:?}); it stays, shadowed\n",
                    old,
                    e
                ),
            }
        }
        self.valid_records = self.slots.iter().filter(|slot| slot.used).count();
        Ok(())
    }

    pub(crate) fn delete(&mut self, key: &Key) -> Result<bool> {
        if !valid_key(key) {
            return Err(EINVAL);
        }
        let Some(idx) = self.find(key) else {
            return Ok(false);
        };
        if !self.writes_enabled {
            return Err(EROFS);
        }
        if let Some(guard) = self.guard.as_mut() {
            guard.check(key, false)?;
        }
        // Every slot of the key goes, the shadowed older ones (a write whose
        // old slot could not be cleared) first and the newest last: a crash
        // part-way leaves the newest, so the key reads as before the delete.
        // An older slot that cannot be cleared stops the delete before the
        // newest, which would otherwise bring it back.
        loop {
            let oldest = self
                .slots
                .iter()
                .enumerate()
                .filter(|&(i, slot)| i != idx && slot.matches(key))
                .min_by_key(|&(i, slot)| (slot.revision, i))
                .map(|(i, _)| i);
            let Some(old) = oldest else {
                break;
            };
            if let Err(e) = self.delete_slot(old) {
                self.valid_records = self.slots.iter().filter(|slot| slot.used).count();
                return Err(e);
            }
            self.slots[old] = Slot::FREE;
        }
        let done = self.delete_slot(idx);
        if done.is_ok() {
            self.slots[idx] = Slot::FREE;
        }
        self.valid_records = self.slots.iter().filter(|slot| slot.used).count();
        done.map(|()| true)
    }

    /// Whether this store accepts writes: `xart_writes=1` and APFS proved the
    /// extent writable.
    pub(crate) fn writes_enabled(&self) -> bool {
        self.writes_enabled
    }

    /// Every live record's key, for the guard's view of what predates it.
    pub(crate) fn live_keys(&self) -> Result<KVec<Key>> {
        let mut keys = KVec::new();
        for slot in self.slots.iter().filter(|slot| slot.used) {
            keys.push(slot.key, GFP_KERNEL)?;
        }
        Ok(keys)
    }

    /// From now on, refuses the enclave's writes to records Linux did not
    /// create. See [`crate::xart_guard`].
    pub(crate) fn set_guard(&mut self, level: u8) -> Result<()> {
        let keys = self.live_keys()?;
        self.guard = Some(crate::xart_guard::Guard::open(level, keys));
        Ok(())
    }

    /// Byte offset of the APFS-resolved gigalocker extent in the container.
    pub(crate) fn base(&self) -> u64 {
        self.base
    }

    pub(crate) fn summary(&self) -> Summary {
        Summary {
            slots: self.slots.len(),
            records: self.valid_records,
            revision: self.revision,
            malformed: self.malformed_records,
            unbacked: self.unbacked_records,
            foreign: self.foreign_records,
            duplicates: self.duplicate_records,
            conflicting: self.conflicting_records,
            repaired: self.repaired_records,
            writable: self.writes_enabled,
        }
    }
}

/// Reflected CRC-32/ISO-HDLC (the IEEE CRC-32 used in gigalocker records).
pub(crate) const fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    let mut i = 0;
    while i < data.len() {
        crc ^= data[i] as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
            bit += 1;
        }
        i += 1;
    }
    crc ^ 0xffff_ffff
}

static_assert!(crc32_ieee(b"123456789") == 0xcbf4_3926);
