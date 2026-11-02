// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! One keybag per Linux user, for `/dev/sep-key`.
//!
//! The T6020 enclave holds several user bags loaded and unlocked at once, each
//! with its own lock state, and a ref key works only under the bag that made
//! it: another bag answers -7 (tanabota sep-key K0, 2 of 2 bags, 4 of 4 cross
//! ops, also after a reboot). So the bag is the isolation between users, in the
//! enclave, not here.
//!
//! A user's bag is made on the user's first CREATE, with the identity bag's
//! create shape and a fresh secret, and kept in
//! `/var/lib/tanabota-sep-bag-<uid>.bin` (root only): the enclave-wrapped bag
//! and its secret. It is loaded and unlocked at the user's first operation and
//! unloaded when the user's last open file closes. A bag the enclave has
//! forgotten (a stale handle, -2: a sleep, a SEP reset) is loaded again once.
//!
//! As macOS does at login (LOAD, DESIGNATE {1, -501}), every loaded bag of a
//! uid of 10 or more is designated to its own SEP user -uid, and its ops
//! address -uid: a designation takes any user from 10 up and lasts the boot,
//! also past an unload of the load handle (tanabota U-A card 5, U-B card 6).
//! That names SEP user uid for Touch ID too (op33, `cbio`), and makes the
//! bag's secret changeable (op 0x07 works on a designated handle). Not for
//! the fingers' user ([`crate::SBIO_PROBE_USER_ID`]): -1000 is the identity
//! bag's, and that uid's own bag only serves its keys from before it.

use core::fmt::Write;

use kernel::prelude::*;

use crate::sks::KeyBagHandle;
use crate::store::crc16_ccitt_false;
use crate::{image, shim, LockState, Secret, SepData, SksRequest};

const MAGIC: [u8; 16] = *b"TANABOTA-SEPBAG1";
const VERSION: u32 = 1;
/// A secret of another length than [`crate::SKS_SECRET_LEN`] (a login
/// password after SEP_KEY_CHANGE_SECRET): u32 its length at [`OFF_SECRET`],
/// then the secret, then the bag. A 32 B secret is still written as v1, so a
/// kernel from before reads every record a random rekey leaves.
const VERSION_SECRET_LEN: u32 = 2;
/// The longest secret a v2 record holds (SEP_KEY_CHANGE_SECRET's maximum).
pub(crate) const SECRET_MAX: usize = 128;

// MAGIC, u32 version, u32 uid, u32 wrapped length, u16 crc (over the whole
// record with this field zero), u16 flags (0 before uid 1000's home moved
// here), the bag UUID, the secret, the bag (v2: u32 secret length, the
// secret, the bag).
const OFF_VERSION: usize = 0x10;
const OFF_UID: usize = 0x14;
const OFF_LEN: usize = 0x18;
const OFF_CRC: usize = 0x1c;
const OFF_FLAGS: usize = 0x1e;
const OFF_UUID: usize = 0x20;
const OFF_SECRET: usize = 0x30;
const HEADER: usize = OFF_SECRET + crate::SKS_SECRET_LEN;
const UUID_LEN: usize = 16;

static_assert!(OFF_UUID + UUID_LEN == OFF_SECRET);
static_assert!(HEADER == 0x50);

const MAX_WRAPPED: usize = 8192;

/// The uuid is the bag's own, read back after its create (the identity
/// record's state 3); else the one the host created it with.
const FLAG_READBACK: u16 = 1;
/// The uid's home record: for [`crate::SBIO_PROBE_USER_ID`], the bag the
/// identity record named, moved here (keybag.rs); its keys from before
/// interface 4 stay in its old own bag, now at the `.legacy.bin` path.
const FLAG_HOME: u16 = 2;
/// Password mode (R2): the record stores no secret (a v2 record of secret
/// length 0); the bag opens with the password SEP_KEY_UNLOCK brings, and
/// stays closed from boot until then.
pub(crate) const FLAG_PASSWORD: u16 = 4;
/// The bag's password is the user's login password, as far as the last
/// unlock showed: PAM's try with the login password is sent to the enclave
/// only then, so a different login password costs no wrong attempt.
pub(crate) const FLAG_LOGIN_SAME: u16 = 8;

/// How long a user-bag exchange may wait. Under the HV the hwrng's entropy
/// requests at boot held a CREATE_KEYBAG back 3.8 s (sep-key bench, 1 of 1),
/// past the driver's 2 s, and a timeout condemns the key store for the boot.
pub(crate) const PATIENCE_MS: kernel::time::Msecs = 10_000;

/// The enclave's status for a handle it does not know (K0: an unloaded bag).
const STATUS_STALE_HANDLE: i8 = -2;

pub(crate) struct UserBag {
    uid: u32,
    handle: Option<KeyBagHandle>,
    files: u32,
}

/// The SEP user a uid's bag is designated to, if it is: 10 and up (the
/// enclave's floor, macOS's too), never the fingers' user.
fn designated_user(uid: u32) -> Option<crate::sks::DesignateUser> {
    let u = i32::try_from(uid).ok()?;
    if u == crate::SBIO_PROBE_USER_ID {
        return None;
    }
    crate::sks::DesignateUser::new(u)
}

/// The handle an op on `uid`'s bag addresses: -uid when designated.
fn op_handle(uid: u32, handle: KeyBagHandle) -> i32 {
    designated_user(uid).map_or(handle.value(), |u| u.special_handle().value())
}

/// The users with an open `/dev/sep-key` and their loaded bags.
pub(crate) struct UserBags {
    list: KVec<UserBag>,
}

impl UserBags {
    pub(crate) fn new() -> UserBags {
        UserBags { list: KVec::new() }
    }

    fn find(&mut self, uid: u32) -> Option<&mut UserBag> {
        self.list.iter_mut().find(|b| b.uid == uid)
    }

    pub(crate) fn loaded(&self, uid: u32) -> bool {
        self.list.iter().any(|b| b.uid == uid && b.handle.is_some())
    }
}

/// `/var/lib/tanabota-sep-bag-<uid>.bin`, NUL-terminated.
struct BagPath {
    buf: [u8; 64],
    len: usize,
}

impl Write for BagPath {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.len + s.len();
        // One byte stays for the NUL.
        if end >= self.buf.len() {
            return Err(core::fmt::Error);
        }
        self.buf[self.len..end].copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

impl BagPath {
    fn new(uid: u32) -> Result<BagPath> {
        let mut p = BagPath {
            buf: [0; 64],
            len: 0,
        };
        write!(p, "/var/lib/tanabota-sep-bag-{}.bin", uid).map_err(|_| EINVAL)?;
        Ok(p)
    }

    /// `/var/lib/tanabota-sep-bag-<uid>.legacy.bin`: uid 1000's own bag from
    /// before interface 4, moved aside when its home record took the path.
    fn legacy(uid: u32) -> Result<BagPath> {
        let mut p = BagPath {
            buf: [0; 64],
            len: 0,
        };
        write!(p, "/var/lib/tanabota-sep-bag-{}.legacy.bin", uid).map_err(|_| EINVAL)?;
        Ok(p)
    }

    /// `/var/lib/tanabota-sep-bag-<uid>.retired-<8 hex>.bin`: a home record
    /// SEP_KEY_NEW_BAG replaced, named by its bag's uuid.
    fn retired(uid: u32, uuid: &[u8; UUID_LEN]) -> Result<BagPath> {
        let mut p = BagPath {
            buf: [0; 64],
            len: 0,
        };
        write!(
            p,
            "/var/lib/tanabota-sep-bag-{}.retired-{:02x}{:02x}{:02x}{:02x}.bin",
            uid, uuid[0], uuid[1], uuid[2], uuid[3]
        )
        .map_err(|_| EINVAL)?;
        Ok(p)
    }

    /// `/var/lib/tanabota-sep-bags-<uid>.idx`: the uuids of `uid`'s retired
    /// records (the store has no directory listing).
    fn index(uid: u32) -> Result<BagPath> {
        let mut p = BagPath {
            buf: [0; 64],
            len: 0,
        };
        write!(p, "/var/lib/tanabota-sep-bags-{}.idx", uid).map_err(|_| EINVAL)?;
        Ok(p)
    }

    /// Where userbag's own ops keep `uid`'s bag: the fingers' user's own bag
    /// is the legacy one (its home is keybag.rs's, at [`BagPath::new`]).
    fn own(uid: u32) -> Result<BagPath> {
        if uid as i32 == crate::SBIO_PROBE_USER_ID {
            BagPath::legacy(uid)
        } else {
            BagPath::new(uid)
        }
    }

    fn as_cstr(&self) -> &CStr {
        // `write_str` keeps the byte after `len` zero and never writes a NUL.
        CStr::from_bytes_with_nul(&self.buf[..=self.len]).unwrap_or(c"")
    }
}

struct StoredBag {
    uuid: [u8; UUID_LEN],
    flags: u16,
    wrapped: KVec<u8>,
    secret: Secret,
}

fn record_crc(rec: &[u8]) -> u16 {
    // The crc field counts as zero; the record is small, so a copy is fine.
    let mut tmp = Secret(KVec::new());
    if tmp.0.extend_from_slice(rec, GFP_KERNEL).is_err() {
        return 0;
    }
    tmp.0[OFF_CRC] = 0;
    tmp.0[OFF_CRC + 1] = 0;
    crc16_ccitt_false(&tmp)
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// The user's stored bag; `None` when there is none (no file, or an empty one
/// left by a create the enclave refused). A record that does not check out is
/// EUCLEAN: never replaced here, since the user's keys need that bag.
fn read(uid: u32) -> Result<Option<StoredBag>> {
    read_at(&BagPath::own(uid)?, uid)
}

fn read_at(path: &BagPath, uid: u32) -> Result<Option<StoredBag>> {
    let f = match shim::StoreFile::open_readonly(path.as_cstr()) {
        Ok(f) => f,
        // Only a missing file is "no bag": any other failure to open says
        // nothing about whether one exists.
        Err(e) if e == ENOENT => return Ok(None),
        Err(e) => return Err(e),
    };
    let size = f.size()? as usize;
    if size == 0 {
        return Ok(None);
    }
    if !(HEADER + 1..=OFF_SECRET + 4 + SECRET_MAX + MAX_WRAPPED).contains(&size) {
        return Err(crate::key::errno::uclean());
    }
    // The record holds the bag's secret: wiped when dropped.
    let mut rec = Secret(KVec::new());
    rec.0.resize(size, 0, GFP_KERNEL)?;
    f.read_exact(0, &mut rec.0)?;
    let crc = u16::from_le_bytes([rec[OFF_CRC], rec[OFF_CRC + 1]]);
    let (secret_at, secret_len) = match u32_at(&rec, OFF_VERSION) {
        VERSION => (OFF_SECRET, crate::SKS_SECRET_LEN),
        VERSION_SECRET_LEN if size > OFF_SECRET + 4 => (OFF_SECRET + 4, u32_at(&rec, OFF_SECRET) as usize),
        _ => return Err(crate::key::errno::uclean()),
    };
    let bag_at = secret_at + secret_len;
    let flags = u16::from_le_bytes([rec[OFF_FLAGS], rec[OFF_FLAGS + 1]]);
    if rec[..OFF_VERSION] != MAGIC
        || (secret_len == 0) != (flags & FLAG_PASSWORD != 0)
        || secret_len > SECRET_MAX
        || bag_at >= size
        || u32_at(&rec, OFF_UID) != uid
        || u32_at(&rec, OFF_LEN) as usize != size - bag_at
        || crc != record_crc(&rec)
    {
        return Err(crate::key::errno::uclean());
    }
    let mut wrapped = KVec::new();
    wrapped.extend_from_slice(&rec[bag_at..], GFP_KERNEL)?;
    let mut secret = KVec::new();
    secret.extend_from_slice(&rec[secret_at..bag_at], GFP_KERNEL)?;
    let mut uuid = [0u8; UUID_LEN];
    uuid.copy_from_slice(&rec[OFF_UUID..OFF_UUID + UUID_LEN]);
    Ok(Some(StoredBag {
        uuid,
        flags,
        wrapped,
        secret: Secret(secret),
    }))
}

pub(crate) fn stored(uid: u32) -> bool {
    matches!(read(uid), Ok(Some(_)))
}

/// As [`stored`], with a record that does not check out (EUCLEAN) or cannot
/// be read an error, not "none".
pub(crate) fn stored_checked(uid: u32) -> Result<bool> {
    read(uid).map(|b| b.is_some())
}

/// Stores the record with one atomic replace of the user's file, so a crash
/// keeps the empty claim file or leaves the whole record, never a torn one.
fn write(
    path: &BagPath,
    uid: u32,
    uuid: &[u8; UUID_LEN],
    secret: &[u8],
    wrapped: &[u8],
) -> Result<()> {
    write_flags(path, uid, 0, uuid, secret, wrapped)
}

fn write_flags(
    path: &BagPath,
    uid: u32,
    flags: u16,
    uuid: &[u8; UUID_LEN],
    secret: &[u8],
    wrapped: &[u8],
) -> Result<()> {
    let password = flags & FLAG_PASSWORD != 0;
    if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED || secret.is_empty() != password || secret.len() > SECRET_MAX {
        return Err(EINVAL);
    }
    let v1 = secret.len() == crate::SKS_SECRET_LEN;
    let mut rec = Secret(KVec::new());
    let rec = &mut rec.0;
    rec.extend_from_slice(&MAGIC, GFP_KERNEL)?;
    rec.extend_from_slice(&(if v1 { VERSION } else { VERSION_SECRET_LEN }).to_le_bytes(), GFP_KERNEL)?;
    rec.extend_from_slice(&uid.to_le_bytes(), GFP_KERNEL)?;
    rec.extend_from_slice(&(wrapped.len() as u32).to_le_bytes(), GFP_KERNEL)?;
    rec.extend_from_slice(&[0; 2], GFP_KERNEL)?;
    rec.extend_from_slice(&flags.to_le_bytes(), GFP_KERNEL)?;
    rec.extend_from_slice(uuid, GFP_KERNEL)?;
    if !v1 {
        rec.extend_from_slice(&(secret.len() as u32).to_le_bytes(), GFP_KERNEL)?;
    }
    rec.extend_from_slice(secret, GFP_KERNEL)?;
    rec.extend_from_slice(wrapped, GFP_KERNEL)?;
    let crc = record_crc(rec);
    rec[OFF_CRC..OFF_CRC + 2].copy_from_slice(&crc.to_le_bytes());
    shim::replace_file(path.as_cstr(), rec)
}

/// A uid's home record (keybag.rs keeps the fingers' user's bag here).
pub(crate) struct HomeRecord {
    pub(crate) uuid: [u8; UUID_LEN],
    pub(crate) readback: bool,
    /// [`FLAG_PASSWORD`] and [`FLAG_LOGIN_SAME`] as stored.
    pub(crate) mode: u16,
    pub(crate) wrapped: KVec<u8>,
    pub(crate) secret: Secret,
}

/// What `tanabota-sep-bag-<uid>.bin` holds for keybag.rs's migration.
pub(crate) enum HomeFile {
    /// No file, or an empty one.
    Missing,
    /// A record without [`FLAG_HOME`]: the uid's own bag from before.
    Legacy,
    Home(HomeRecord),
}

/// `uid`'s file at the home path, as [`HomeFile`]; a record that does not
/// check out is EUCLEAN.
pub(crate) fn read_home(uid: u32) -> Result<HomeFile> {
    Ok(match read_at(&BagPath::new(uid)?, uid)? {
        None => HomeFile::Missing,
        Some(b) if b.flags & FLAG_HOME == 0 => HomeFile::Legacy,
        Some(b) => HomeFile::Home(HomeRecord {
            uuid: b.uuid,
            readback: b.flags & FLAG_READBACK != 0,
            mode: b.flags & (FLAG_PASSWORD | FLAG_LOGIN_SAME),
            wrapped: b.wrapped,
            secret: b.secret,
        }),
    })
}

/// Writes `uid`'s home record (one atomic replace of the home path); `mode`
/// is [`FLAG_PASSWORD`] / [`FLAG_LOGIN_SAME`], and with a password no secret
/// is written whatever `secret` holds.
pub(crate) fn write_home(
    uid: u32,
    uuid: &[u8; UUID_LEN],
    readback: bool,
    mode: u16,
    secret: &[u8],
    wrapped: &[u8],
) -> Result<()> {
    let flags = FLAG_HOME | if readback { FLAG_READBACK } else { 0 } | (mode & (FLAG_PASSWORD | FLAG_LOGIN_SAME));
    let secret = if mode & FLAG_PASSWORD != 0 { &[][..] } else { secret };
    write_flags(&BagPath::new(uid)?, uid, flags, uuid, secret, wrapped)
}

/// `uid`'s record at the home path with `set` and `clear` applied to its
/// flags (LOGIN_SAME after an unlock), the rest as it is.
pub(crate) fn update_home_flags(uid: u32, set: u16, clear: u16) -> Result<()> {
    let path = BagPath::new(uid)?;
    let b = read_at(&path, uid)?.ok_or_else(crate::key::errno::nokey)?;
    let flags = (b.flags | set) & !clear;
    if flags == b.flags {
        return Ok(());
    }
    write_flags(&path, uid, flags, &b.uuid, &b.secret, &b.wrapped)
}

/// The mode flags of `uid`'s record at the home path; None without one.
pub(crate) fn home_mode(uid: u32) -> Result<Option<u16>> {
    Ok(read_at(&BagPath::new(uid)?, uid)?.map(|b| b.flags & (FLAG_PASSWORD | FLAG_LOGIN_SAME)))
}

/// SEP_KEY_NEW_BAG: copies `uid`'s home record to its `.retired-<uuid8>.bin`
/// path (created, never over another file; the same bytes there already are
/// a retry) before the home path takes the new bag. Only a password-mode
/// record: it holds no secret, so the copy opens nothing (EINVAL for a
/// stored secret, which would stay on disk with it).
pub(crate) fn retire_home(uid: u32) -> Result<()> {
    let home = BagPath::new(uid)?;
    let b = read_at(&home, uid)?.ok_or_else(crate::key::errno::nokey)?;
    if b.flags & FLAG_PASSWORD == 0 {
        return Err(EINVAL);
    }
    let f = shim::StoreFile::open_readonly(home.as_cstr())?;
    let mut raw = KVec::new();
    raw.resize(f.size()? as usize, 0, GFP_KERNEL)?;
    f.read_exact(0, &mut raw)?;
    let retired = BagPath::retired(uid, &b.uuid)?;
    // listed first: an entry without its file is dropped by tidy(), a file
    // without its entry would be invisible
    index_add(uid, &b.uuid)?;
    match shim::create_file(retired.as_cstr(), &raw) {
        Err(e) if e == EEXIST => {
            let there = raw_file(&retired)?.ok_or(ENOENT)?;
            if there == raw { Ok(()) } else { Err(EEXIST) }
        }
        r => r,
    }
}

fn raw_file(p: &BagPath) -> Result<Option<KVec<u8>>> {
    let f = match shim::StoreFile::open_readonly(p.as_cstr()) {
        Ok(f) => f,
        Err(e) if e == ENOENT => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut b = KVec::new();
    b.resize(f.size()? as usize, 0, GFP_KERNEL)?;
    f.read_exact(0, &mut b)?;
    Ok(Some(b))
}

const INDEX_MAGIC: [u8; 16] = *b"TANABOTA-BAGIDX1";
/// More retired bags than this per uid: delete some first (ENOSPC).
pub(crate) const BAGS_MAX: usize = 16;

/// The retired uuids of `uid`, as the index lists them.
fn index_read(uid: u32) -> Result<KVec<[u8; UUID_LEN]>> {
    let mut out = KVec::new();
    let Some(b) = raw_file(&BagPath::index(uid)?)? else {
        return Ok(out);
    };
    if b.len() < 20 || b[..16] != INDEX_MAGIC {
        return Err(crate::key::errno::uclean());
    }
    let n = u32_at(&b, 16) as usize;
    if n > BAGS_MAX || b.len() != 20 + n * UUID_LEN {
        return Err(crate::key::errno::uclean());
    }
    for i in 0..n {
        let mut u = [0u8; UUID_LEN];
        u.copy_from_slice(&b[20 + i * UUID_LEN..20 + (i + 1) * UUID_LEN]);
        out.push(u, GFP_KERNEL)?;
    }
    Ok(out)
}

fn index_write(uid: u32, list: &[[u8; UUID_LEN]]) -> Result<()> {
    let mut b = KVec::new();
    b.extend_from_slice(&INDEX_MAGIC, GFP_KERNEL)?;
    b.extend_from_slice(&(list.len() as u32).to_le_bytes(), GFP_KERNEL)?;
    for u in list {
        b.extend_from_slice(u, GFP_KERNEL)?;
    }
    shim::replace_file(BagPath::index(uid)?.as_cstr(), &b)
}

fn index_add(uid: u32, uuid: &[u8; UUID_LEN]) -> Result<()> {
    let mut list = index_read(uid)?;
    if list.iter().any(|u| u == uuid) {
        return Ok(());
    }
    if list.len() >= BAGS_MAX {
        return Err(ENOSPC);
    }
    list.push(*uuid, GFP_KERNEL)?;
    index_write(uid, &list)
}

fn index_remove(uid: u32, uuid: &[u8; UUID_LEN]) -> Result<()> {
    let list = index_read(uid)?;
    let mut keep = KVec::new();
    for u in list.iter().filter(|u| *u != uuid) {
        keep.push(*u, GFP_KERNEL)?;
    }
    if keep.len() == list.len() {
        return Ok(());
    }
    index_write(uid, &keep)
}

/// Where a bag of `uid` other than the home one lives.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Role {
    Home = 1,
    Legacy = 2,
    Retired = 3,
}

/// One record of a uid, as SEP_KEY_BAG_LIST shows it.
pub(crate) struct BagEntry {
    pub(crate) uuid: [u8; UUID_LEN],
    pub(crate) role: Role,
    /// FLAG_PASSWORD / FLAG_LOGIN_SAME as stored.
    pub(crate) mode: u16,
}

/// Brings `uid`'s retired records in line with the index, after a crash
/// anywhere in NEW_BAG / BAG_USE / BAG_DELETE: an entry without its file is
/// dropped; a retired record of the home bag's uuid (BAG_USE replaced the
/// home path and was cut short before the source went) is removed.
pub(crate) fn tidy(uid: u32) -> Result<()> {
    let home = read_at(&BagPath::new(uid)?, uid)?.map(|b| b.uuid);
    for u in index_read(uid)?.iter() {
        let p = BagPath::retired(uid, u)?;
        match read_at(&p, uid)? {
            None => index_remove(uid, u)?,
            Some(b) if Some(b.uuid) == home && b.flags & FLAG_PASSWORD != 0 => {
                shim::remove_file(p.as_cstr())?;
                index_remove(uid, u)?;
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Every record of `uid`: the home one, the legacy one (uid 1000's own bag
/// from before), the retired ones.
pub(crate) fn list(uid: u32) -> Result<KVec<BagEntry>> {
    tidy(uid)?;
    let mut out = KVec::new();
    let mode = |f: u16| f & (FLAG_PASSWORD | FLAG_LOGIN_SAME);
    if let Some(b) = read_at(&BagPath::new(uid)?, uid)? {
        // uid 1000's home path holds its legacy own bag until the identity
        // record moved there (keybag.rs): only a home record is the home
        let role = if b.flags & FLAG_HOME != 0 || uid as i32 != crate::SBIO_PROBE_USER_ID { Role::Home } else { Role::Legacy };
        out.push(BagEntry { uuid: b.uuid, role, mode: mode(b.flags) }, GFP_KERNEL)?;
    }
    if let Some(b) = read_at(&BagPath::legacy(uid)?, uid)? {
        out.push(BagEntry { uuid: b.uuid, role: Role::Legacy, mode: mode(b.flags) }, GFP_KERNEL)?;
    }
    for u in index_read(uid)?.iter() {
        if let Some(b) = read_at(&BagPath::retired(uid, u)?, uid)? {
            out.push(BagEntry { uuid: b.uuid, role: Role::Retired, mode: mode(b.flags) }, GFP_KERNEL)?;
        }
    }
    Ok(out)
}

/// The path of `uid`'s non-home record of bag `uuid` and its role, or
/// EBUSY for the home bag, ENOENT for none.
fn find_other(uid: u32, uuid: &[u8; UUID_LEN]) -> Result<(BagPath, Role)> {
    if read_at(&BagPath::new(uid)?, uid)?.is_some_and(|b| b.uuid == *uuid && b.flags & FLAG_HOME != 0) {
        return Err(EBUSY);
    }
    if read_at(&BagPath::legacy(uid)?, uid)?.is_some_and(|b| b.uuid == *uuid) {
        return Ok((BagPath::legacy(uid)?, Role::Legacy));
    }
    if index_read(uid)?.iter().any(|u| u == uuid) {
        let p = BagPath::retired(uid, uuid)?;
        if read_at(&p, uid)?.is_some() {
            return Ok((p, Role::Retired));
        }
    }
    Err(ENOENT)
}

/// SEP_KEY_BAG_DELETE's file part: `uid`'s non-home record of `uuid` goes.
/// A record that holds a secret (stored mode: a legacy bag) is overwritten
/// with zeros and synced first (on a copy-on-write filesystem the old
/// blocks may still survive in it and in its snapshots).
pub(crate) fn delete(uid: u32, uuid: &[u8; UUID_LEN]) -> Result<Role> {
    let (path, role) = find_other(uid, uuid)?;
    let b = read_at(&path, uid)?.ok_or(ENOENT)?;
    if b.flags & FLAG_PASSWORD == 0 {
        let (f, _) = shim::StoreFile::open_host(path.as_cstr())?;
        let mut zeros = KVec::new();
        zeros.resize(f.size()? as usize, 0u8, GFP_KERNEL)?;
        f.write_all(0, &zeros)?;
        f.sync()?;
    }
    shim::remove_file(path.as_cstr())?;
    if role == Role::Retired {
        index_remove(uid, uuid)?;
    }
    Ok(role)
}

/// What SEP_KEY_BAG_USE needs of its target: the record (password mode
/// only: the home bag is never stored-mode again, EINVAL), and its path.
pub(crate) struct UseTarget {
    path: BagPath,
    pub(crate) uuid: [u8; UUID_LEN],
    pub(crate) readback: bool,
    pub(crate) wrapped: KVec<u8>,
    raw: KVec<u8>,
}

pub(crate) fn use_target(uid: u32, uuid: &[u8; UUID_LEN]) -> Result<UseTarget> {
    let (path, _) = find_other(uid, uuid)?;
    let b = read_at(&path, uid)?.ok_or(ENOENT)?;
    if b.flags & FLAG_PASSWORD == 0 {
        return Err(EINVAL);
    }
    let raw = raw_file(&path)?.ok_or(ENOENT)?;
    Ok(UseTarget { uuid: b.uuid, readback: b.flags & FLAG_READBACK != 0, wrapped: b.wrapped, path, raw })
}

/// SEP_KEY_BAG_USE's file part, after the enclave took the target: the home
/// record is retired (copied to its .retired-<uuid8>.bin, listed), the
/// target's record replaces the home path (one atomic replace), the
/// target's own file goes. A crash leaves: before the replace, the old home
/// in place (and maybe its retired copy): the old bag is home, as before; after
/// it, the target is home and its old file a retired record of the home's
/// uuid, which tidy() removes at the next list, use or boot.
pub(crate) fn use_commit(uid: u32, t: &UseTarget) -> Result<()> {
    retire_home(uid)?;
    shim::replace_file(BagPath::new(uid)?.as_cstr(), &t.raw)?;
    tidy(uid)?;
    if read_at(&t.path, uid)?.is_some() {
        // a legacy record cannot be a target (stored mode); a retired one
        // with the home's uuid was removed by tidy()
        shim::remove_file(t.path.as_cstr())?;
    }
    Ok(())
}

/// Moves a legacy record at the home path aside to the `.legacy.bin` path,
/// as a copy created there (never over an existing file); the home path is
/// then replaced by the caller. A crash between the two leaves both: the
/// copy is identical to the record still at the home path, and the next try
/// finds it so and goes on. A different file already at the legacy path is
/// EUCLEAN: which of the two holds the keys cannot be told here.
pub(crate) fn move_legacy_aside(uid: u32) -> Result<()> {
    let home = BagPath::new(uid)?;
    let legacy = BagPath::legacy(uid)?;
    let raw = |p: &BagPath| -> Result<Option<Secret>> {
        let f = match shim::StoreFile::open_readonly(p.as_cstr()) {
            Ok(f) => f,
            Err(e) if e == ENOENT => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut b = Secret(KVec::new());
        b.0.resize(f.size()? as usize, 0, GFP_KERNEL)?;
        f.read_exact(0, &mut b.0)?;
        Ok(Some(b))
    };
    let Some(rec) = raw(&home)? else {
        return Ok(());
    };
    match raw(&legacy)? {
        Some(existing) if existing.0 == rec.0 => Ok(()),
        Some(_) => Err(crate::key::errno::uclean()),
        None => shim::create_file(legacy.as_cstr(), &rec),
    }
}

/// What the enclave answered an operation on a bag: for an ECDH, the shared
/// secret, so the body is wiped when dropped.
pub(crate) struct OpReply {
    pub(crate) status: i8,
    pub(crate) body: KVec<u8>,
}

impl Drop for OpReply {
    fn drop(&mut self) {
        image::wipe(&mut self.body);
    }
}

impl SepData {
    /// The secret SEP_KEY_UNLOCK brought for `uid`'s password-mode bag.
    pub(crate) fn bag_secret(&self, uid: u32) -> Option<Secret> {
        let list = self.bag_secrets.lock();
        let (_, s) = list.iter().find(|(u, _)| *u == uid)?;
        let mut copy = KVec::new();
        copy.extend_from_slice(s, GFP_KERNEL).ok()?;
        Some(Secret(copy))
    }

    pub(crate) fn bag_secret_set(&self, uid: u32, secret: &[u8]) -> Result<()> {
        let mut copy = KVec::new();
        copy.extend_from_slice(secret, GFP_KERNEL)?;
        let mut list = self.bag_secrets.lock();
        if let Some(e) = list.iter_mut().find(|(u, _)| *u == uid) {
            e.1 = Secret(copy);
            return Ok(());
        }
        list.push((uid, Secret(copy)), GFP_KERNEL)?;
        Ok(())
    }

    pub(crate) fn bag_secret_forget(&self, uid: u32) {
        let mut list = self.bag_secrets.lock();
        if let Some(i) = list.iter().position(|(u, _)| *u == uid) {
            // dropping the Secret wipes it
            let _ = list.swap_remove(i);
        }
    }

    /// The identity slot (uid 1000's home bag) with its secret: the stored
    /// one, or in password mode the one SEP_KEY_UNLOCK brought; ENOKEY while
    /// a password-mode bag is closed. What every user of the secret reads.
    pub(crate) fn identity_read(&self) -> Result<crate::keybag::State> {
        match crate::keybag::read(crate::keybag::Slot::Identity)? {
            crate::keybag::State::Present(s) if s.password() => {
                let secret = self.bag_secret(crate::SBIO_PROBE_USER_ID as u32).ok_or_else(crate::key::errno::nokey)?;
                Ok(crate::keybag::State::Present(s.with_secret(secret)))
            }
            other => Ok(other),
        }
    }

    /// A password-mode identity bag not unlocked yet: Touch ID waits.
    pub(crate) fn identity_closed(&self) -> bool {
        matches!(crate::keybag::read(crate::keybag::Slot::Identity),
                 Ok(crate::keybag::State::Present(s)) if s.password())
            && self.bag_secret(crate::SBIO_PROBE_USER_ID as u32).is_none()
    }

    fn user_bag_unlock(&self, handle: KeyBagHandle, secret: &[u8]) -> Result<()> {
        let healthy = self.sks_health_check(c"sep-key unlock").ok_or(EIO)?;
        let out = self
            .sks_send_patient(
                self.sks_req_change_lock_state(handle, LockState::Unlocked, secret, healthy),
                PATIENCE_MS,
            )
            .ok_or(EIO)?;
        if out.reply.status != 0 {
            dev_warn!(
                self.dev,
                "sep-key: unlocking a user bag: mailbox status {}\n",
                out.reply.status
            );
            return Err(EIO);
        }
        Ok(())
    }

    fn user_bag_load(&self, uid: u32, stored: &StoredBag) -> Result<KeyBagHandle> {
        let out = self
            .sks_send_patient(self.sks_req_load_keybag(&stored.wrapped), PATIENCE_MS)
            .ok_or(EIO)?;
        let body = self
            .sks_report_response(crate::sks::SKS_LOAD_NAME, &out)
            .unwrap_or(&[]);
        if out.reply.status != 0 || body.len() != crate::SKS_LOAD_REPLY_LEN {
            dev_warn!(
                self.dev,
                "sep-key: LOAD_KEYBAG for uid {}: mailbox status {}, {} B\n",
                uid,
                out.reply.status,
                body.len()
            );
            return Err(EIO);
        }
        let status = i32::from_le_bytes([body[0], body[1], body[2], body[3]]);
        let raw = i32::from_le_bytes([body[4], body[5], body[6], body[7]]);
        if status != 0 || raw < 0 {
            dev_warn!(
                self.dev,
                "sep-key: LOAD_KEYBAG for uid {}: status {}, handle {}\n",
                uid,
                status,
                raw
            );
            return Err(EIO);
        }
        let handle = KeyBagHandle::from_load_reply(raw);
        let ready = self
            .user_bag_unlock(handle, &stored.secret)
            .and_then(|()| self.user_bag_designate(uid, handle, &stored.secret));
        if let Err(e) = ready {
            let _ = self.sks_send_patient(self.sks_req_unload_keybag(handle), PATIENCE_MS);
            return Err(e);
        }
        Ok(handle)
    }

    /// DESIGNATE {handle, -uid} with the bag's secret (Variant5's carries it),
    /// for a uid that gets one; nothing for the others. A designation made
    /// earlier this boot outlives its load handle (U-B) and is unlocked in
    /// place instead: once SEP_KEY_LOCK closed it, a DESIGNATE onto it again
    /// is refused (tanabota U-N1: mailbox status -1 after LOCK). -2 there
    /// means none yet: DESIGNATE. `secret` is one that already opened the bag.
    fn user_bag_designate(&self, uid: u32, handle: KeyBagHandle, secret: &[u8]) -> Result<()> {
        let Some(user) = designated_user(uid) else {
            return Ok(());
        };
        let healthy = self.sks_health_check(c"sep-key designate").ok_or(EIO)?;
        if let Some(out) = self.sks_send_patient(
            self.sks_req_unlock_special(user.special_handle(), secret, healthy),
            PATIENCE_MS,
        ) {
            if out.reply.status == 0 {
                return Ok(());
            }
        }
        let d = crate::sks::Designation::new(handle, user);
        let out = self
            .sks_send_patient(self.sks_req_designate(&d, secret), PATIENCE_MS)
            .ok_or(EIO)?;
        let body = self
            .sks_report_response(crate::sks::SKS_DESIGNATE_NAME, &out)
            .unwrap_or(&[]);
        if out.reply.status != 0 || body.len() != crate::sks::SKS_DESIGNATE_REPLY_LEN {
            dev_warn!(
                self.dev,
                "sep-key: DESIGNATE uid {}'s bag: mailbox status {}, {} B\n",
                uid,
                out.reply.status,
                body.len()
            );
            return Err(EIO);
        }
        Ok(())
    }

    /// CREATE_KEYBAG as the identity bag's T6020 create (E6, K0), then
    /// COPY_KEYBAG into the user's file, then unlock. The file is opened with
    /// O_EXCL first, so an existing bag is never replaced; an empty one is a
    /// create the enclave refused, and is retried.
    fn user_bag_create(&self, uid: u32) -> Result<KeyBagHandle> {
        if self.profile.key_store != crate::profile::KeyStore::Variant5 {
            return Err(crate::key::errno::opnotsupp());
        }
        let path = BagPath::own(uid)?;
        let (file, created) = shim::StoreFile::open_host(path.as_cstr())?;
        if !created && file.size()? != 0 {
            return Err(EEXIST);
        }
        drop(file);
        // Wiped on every way out.
        let mut secret = Secret(KVec::new());
        secret.0.resize(crate::SKS_SECRET_LEN, 0, GFP_KERNEL)?;
        let mut uuid = [0u8; UUID_LEN];
        shim::random_bytes(&mut secret.0)?;
        shim::random_bytes(&mut uuid)?;
        uuid[6] = (uuid[6] & 0x0f) | 0x40;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;

        let enc = &self.profile.keybag_create;
        let mut body = image::Body::new();
        body.put_u32(enc.variant)?;
        body.put_u64(crate::sks::SKS_CLIENT_ID)?;
        body.put_u32(enc.bag_type)?;
        body.put_i32(enc.arg)?;
        body.put_blob(&secret)?;
        body.put_blob(&[])?;
        body.put_blob(&uuid)?;
        body.put_blob(&[])?;
        body.put_u64(0)?;
        body.put_u64(0)?;
        body.put_blob(&[])?;
        let img = image::build_request(self.sks_ipc_version(), self.sks_timestamp_us(), &body)?;
        let len = self.sks_image_len(&img)?;
        let msg = crate::sks::encode_sks_create(self.sks_next_seq(), len).ok_or(EINVAL)?;
        let out = self
            .sks_send_patient(
                Ok(SksRequest {
                    name: crate::sks::SKS_CREATE_NAME,
                    msg,
                    img,
                }),
                PATIENCE_MS,
            )
            .ok_or(EIO)?;
        let reply = self
            .sks_report_response(crate::sks::SKS_CREATE_NAME, &out)
            .unwrap_or(&[]);
        if out.reply.status != 0 || reply.len() < 8 {
            dev_warn!(
                self.dev,
                "sep-key: CREATE_KEYBAG for uid {}: mailbox status {}, {} B\n",
                uid,
                out.reply.status,
                reply.len()
            );
            return Err(EIO);
        }
        let raw = i32::from_le_bytes([reply[4], reply[5], reply[6], reply[7]]);
        if raw < 0 {
            return Err(EIO);
        }
        let handle = KeyBagHandle::from_create_reply(raw);
        let copied = self
            .sks_send_patient(self.sks_req_copy_keybag(handle), PATIENCE_MS)
            .and_then(|c| self.wrapped_from_copy_reply(&c, c"user bag"));
        let Some(wrapped) = copied else {
            dev_err!(self.dev, "sep-key: COPY_KEYBAG of uid {}'s new bag failed\n", uid);
            let _ = self.sks_send_patient(self.sks_req_unload_keybag(handle), PATIENCE_MS);
            return Err(EIO);
        };
        if let Err(e) = write(&path, uid, &uuid, &secret, &wrapped) {
            dev_err!(self.dev, "sep-key: storing uid {}'s bag failed: {:?}\n", uid, e);
            let _ = self.sks_send_patient(self.sks_req_unload_keybag(handle), PATIENCE_MS);
            return Err(e);
        }
        dev_info!(self.dev, "sep-key: created the keybag of uid {}\n", uid);
        let ready = self
            .user_bag_unlock(handle, &secret)
            .and_then(|()| self.user_bag_designate(uid, handle, &secret));
        if let Err(e) = ready {
            let _ = self.sks_send_patient(self.sks_req_unload_keybag(handle), PATIENCE_MS);
            return Err(e);
        }
        Ok(handle)
    }

    fn user_bag_handle(&self, bag: &mut UserBag, create: bool) -> Result<KeyBagHandle> {
        if let Some(h) = bag.handle {
            return Ok(h);
        }
        let handle = match read(bag.uid)? {
            Some(mut stored) => {
                if stored.flags & FLAG_PASSWORD != 0 {
                    // closed until SEP_KEY_UNLOCK brings its password
                    stored.secret = self.bag_secret(bag.uid).ok_or_else(crate::key::errno::nokey)?;
                }
                self.user_bag_load(bag.uid, &stored)?
            }
            None if create => self.user_bag_create(bag.uid)?,
            None => return Err(crate::key::errno::nokey()),
        };
        bag.handle = Some(handle);
        Ok(handle)
    }

    /// One PERFORM_OPERATION on `uid`'s bag; `create` makes the bag first if
    /// the user has none.
    pub(crate) fn user_bag_op(
        &self,
        bags: &mut UserBags,
        uid: u32,
        create: bool,
        der: &[u8],
    ) -> Result<OpReply> {
        let bag = bags.find(uid).ok_or(EBADF)?;
        let mut retried = false;
        loop {
            let handle = self.user_bag_handle(bag, create)?;
            let out = self
                .sks_send_patient(self.sks_req_refkey(op_handle(uid, handle), der), PATIENCE_MS)
                .ok_or(EIO)?;
            // -2 also when the enclave lost the designation (a SEP reset): the
            // reload designates again.
            if out.reply.status == STATUS_STALE_HANDLE && !retried {
                dev_info!(self.dev, "sep-key: uid {}'s bag went stale; loading it again\n", uid);
                bag.handle = None;
                retried = true;
                continue;
            }
            let mut body = KVec::new();
            if out.reply.status == 0 {
                let b = self
                    .sks_report_response(crate::sks::SKS_PERFORM_OP_NAME, &out)
                    .ok_or(EIO)?;
                body.extend_from_slice(b, GFP_KERNEL)?;
            }
            return Ok(OpReply {
                status: out.reply.status,
                body,
            });
        }
    }

    /// SEP_KEY_CHANGE_SECRET on `uid`'s own bag: op 0x07 on -uid from `old`
    /// (the record's when `None`) to `new`, COPY_KEYBAG on -uid (the load
    /// handle still gives the bytes from before, tanabota U-J), and one atomic
    /// replace of the record with the new copy and `new`. EOPNOTSUPP for a
    /// uid whose bag is not designated. The enclave's status in `status`.
    ///
    /// If the record is not rewritten after the enclave said yes, the old
    /// record still opens with the old secret (no generation, U-J): the bag
    /// keeps working until it is loaded again, then the change is lost.
    ///
    /// `mode` ([`FLAG_PASSWORD`], [`FLAG_LOGIN_SAME`]) is the bag's after
    /// the change. A password-mode bag changes only open and with `old`
    /// given (EINVAL without), so a process of the user cannot replace a
    /// password it never knew.
    pub(crate) fn user_bag_change_secret(
        &self,
        bags: &mut UserBags,
        uid: u32,
        old: Option<&[u8]>,
        new: &[u8],
        mode: u16,
        status: &mut i32,
    ) -> Result<()> {
        let Some(user) = designated_user(uid) else {
            return Err(crate::key::errno::opnotsupp());
        };
        let special = user.special_handle();
        let bag = bags.find(uid).ok_or(EBADF)?;
        let mut stored = read(uid)?.ok_or_else(crate::key::errno::nokey)?;
        if stored.flags & FLAG_PASSWORD != 0 {
            if old.is_none() {
                return Err(EINVAL);
            }
            stored.secret = self.bag_secret(uid).ok_or_else(crate::key::errno::nokey)?;
        }
        let mut retried = false;
        loop {
            self.user_bag_handle(bag, false)?;
            let out = self
                .sks_send_patient(
                    self.sks_req_change_secret(special, old.unwrap_or(&stored.secret), new),
                    PATIENCE_MS,
                )
                .ok_or(EIO)?;
            if out.reply.status == STATUS_STALE_HANDLE && !retried {
                bag.handle = None;
                retried = true;
                continue;
            }
            *status = out.reply.status as i32;
            if out.reply.status != 0 {
                return Err(EACCES);
            }
            break;
        }
        let fresh = self
            .sks_send_patient(self.sks_req_copy_keybag_special(special), PATIENCE_MS)
            .and_then(|out| self.wrapped_from_copy_reply(&out, c"a user bag after its change"));
        let written = match fresh {
            Some(fresh) => BagPath::own(uid).and_then(|path| {
                let flags = (stored.flags & !(FLAG_PASSWORD | FLAG_LOGIN_SAME)) | mode;
                let secret = if mode & FLAG_PASSWORD != 0 { &[][..] } else { new };
                write_flags(&path, uid, flags, &stored.uuid, secret, &fresh)
            }),
            None => Err(EIO),
        };
        if let Err(e) = written {
            dev_err!(
                self.dev,
                "sep-key: uid {}'s bag secret changed in the enclave but its record was not rewritten ({:?}); the old record stays valid until the bag is loaded again\n",
                uid,
                e
            );
            return Err(EIO);
        }
        if mode & FLAG_PASSWORD != 0 {
            self.bag_secret_set(uid, new)?;
        } else {
            self.bag_secret_forget(uid);
        }
        dev_info!(self.dev, "sep-key: uid {}'s bag secret changed\n", uid);
        Ok(())
    }

    /// SEP_KEY_UNLOCK's check of `secret` on `uid`'s own password-mode bag:
    /// LOAD, CHANGE_LOCK_STATE 0 with it, DESIGNATE -uid on success (the
    /// designation outlives the load handle, U-B), UNLOAD. The enclave's
    /// status of the unlock (-5: not the secret).
    pub(crate) fn user_bag_verify(&self, _bags: &mut UserBags, uid: u32, secret: &[u8]) -> Result<i8> {
        let stored = read(uid)?.ok_or_else(crate::key::errno::nokey)?;
        if stored.flags & FLAG_PASSWORD == 0 {
            return Err(EINVAL);
        }
        let out = self
            .sks_send_patient(self.sks_req_load_keybag(&stored.wrapped), PATIENCE_MS)
            .ok_or(EIO)?;
        let body = self.sks_report_response(crate::sks::SKS_LOAD_NAME, &out).unwrap_or(&[]);
        if out.reply.status != 0 || body.len() != crate::SKS_LOAD_REPLY_LEN {
            return Err(EIO);
        }
        let raw = i32::from_le_bytes([body[4], body[5], body[6], body[7]]);
        if raw < 0 {
            return Err(EIO);
        }
        let handle = KeyBagHandle::from_load_reply(raw);
        let result = (|| {
            let healthy = self.sks_health_check(c"sep-key unlock").ok_or(EIO)?;
            let out = self
                .sks_send_patient(self.sks_req_change_lock_state(handle, LockState::Unlocked, secret, healthy), PATIENCE_MS)
                .ok_or(EIO)?;
            if out.reply.status != 0 {
                return Ok(out.reply.status);
            }
            self.user_bag_designate(uid, handle, secret)?;
            Ok(0)
        })();
        let _ = self.sks_send_patient(self.sks_req_unload_keybag(handle), PATIENCE_MS);
        result
    }

    /// SEP_KEY_LOCK on `uid`'s own bag: CHANGE_LOCK_STATE 1 on -uid, its load
    /// handle unloaded, its secret forgotten; ops are ENOKEY until UNLOCK.
    pub(crate) fn user_bag_lock(&self, bags: &mut UserBags, uid: u32) -> Result<()> {
        let user = designated_user(uid).ok_or_else(crate::key::errno::opnotsupp)?;
        if !matches!(read(uid)?, Some(b) if b.flags & FLAG_PASSWORD != 0) {
            return Err(EINVAL);
        }
        self.bag_secret_forget(uid);
        // -2 when nothing designated it this boot: closed already
        let _ = self.sks_send_patient(self.sks_req_lock_special(user.special_handle()), PATIENCE_MS);
        if let Some(bag) = bags.find(uid) {
            if let Some(h) = bag.handle.take() {
                let _ = self.sks_send_patient(self.sks_req_unload_keybag(h), PATIENCE_MS);
            }
        }
        Ok(())
    }

    pub(crate) fn user_bag_open(&self, bags: &mut UserBags, uid: u32) -> Result<()> {
        if let Some(bag) = bags.find(uid) {
            bag.files += 1;
            return Ok(());
        }
        bags.list.push(
            UserBag {
                uid,
                handle: None,
                files: 1,
            },
            GFP_KERNEL,
        )?;
        Ok(())
    }

    /// The system is about to sleep: unload every loaded bag while the
    /// enclave still knows them, and forget every handle whatever the unload
    /// answered. A handle kept across a sleep may name another uid's bag by
    /// then; forgetting one whose unload was lost only leaks that load. The
    /// next operation loads the user's bag again.
    pub(crate) fn user_bags_sleep(&self) {
        let mut bags = self.user_bags.lock();
        for bag in bags.list.iter_mut() {
            let Some(h) = bag.handle.take() else {
                continue;
            };
            match self.sks_send_patient(self.sks_req_unload_keybag(h), PATIENCE_MS) {
                Some(out) if out.reply.status == 0 => {}
                Some(out) => dev_warn!(
                    self.dev,
                    "sep-key: unloading uid {}'s bag before sleep: status {}\n",
                    bag.uid,
                    out.reply.status
                ),
                None => dev_warn!(
                    self.dev,
                    "sep-key: unloading uid {}'s bag before sleep: no answer\n",
                    bag.uid
                ),
            }
        }
    }

    /// SEP_KEY_NEW_BAG on `uid`'s own bag: the old bag's load handle goes,
    /// so the next op loads the new record.
    pub(crate) fn user_bag_forget_handle(&self, bags: &mut UserBags, uid: u32) {
        if let Some(bag) = bags.find(uid) {
            if let Some(h) = bag.handle.take() {
                let _ = self.sks_send_patient(self.sks_req_unload_keybag(h), PATIENCE_MS);
            }
        }
    }

    /// The user's last file closed: unload the bag.
    pub(crate) fn user_bag_close(&self, bags: &mut UserBags, uid: u32) {
        let Some(i) = bags.list.iter().position(|b| b.uid == uid) else {
            return;
        };
        bags.list[i].files -= 1;
        if bags.list[i].files != 0 {
            return;
        }
        if let Some(h) = bags.list[i].handle {
            let _ = self.sks_send_patient(self.sks_req_unload_keybag(h), PATIENCE_MS);
        }
        let _ = bags.list.swap_remove(i);
    }
}
