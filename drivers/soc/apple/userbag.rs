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
// record with this field zero), u16 0, the bag UUID, the secret, the bag
// (v2: u32 secret length, the secret, the bag).
const OFF_VERSION: usize = 0x10;
const OFF_UID: usize = 0x14;
const OFF_LEN: usize = 0x18;
const OFF_CRC: usize = 0x1c;
const OFF_UUID: usize = 0x20;
const OFF_SECRET: usize = 0x30;
const HEADER: usize = OFF_SECRET + crate::SKS_SECRET_LEN;
const UUID_LEN: usize = 16;

static_assert!(OFF_UUID + UUID_LEN == OFF_SECRET);
static_assert!(HEADER == 0x50);

const MAX_WRAPPED: usize = 8192;

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
    buf: [u8; 48],
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
            buf: [0; 48],
            len: 0,
        };
        write!(p, "/var/lib/tanabota-sep-bag-{}.bin", uid).map_err(|_| EINVAL)?;
        Ok(p)
    }

    fn as_cstr(&self) -> &CStr {
        // `write_str` keeps the byte after `len` zero and never writes a NUL.
        CStr::from_bytes_with_nul(&self.buf[..=self.len]).unwrap_or(c"")
    }
}

struct StoredBag {
    uuid: [u8; UUID_LEN],
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
    let path = BagPath::new(uid)?;
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
    if rec[..OFF_VERSION] != MAGIC
        || secret_len == 0
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
    if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED || secret.is_empty() || secret.len() > SECRET_MAX {
        return Err(EINVAL);
    }
    let v1 = secret.len() == crate::SKS_SECRET_LEN;
    let mut rec = Secret(KVec::new());
    let rec = &mut rec.0;
    rec.extend_from_slice(&MAGIC, GFP_KERNEL)?;
    rec.extend_from_slice(&(if v1 { VERSION } else { VERSION_SECRET_LEN }).to_le_bytes(), GFP_KERNEL)?;
    rec.extend_from_slice(&uid.to_le_bytes(), GFP_KERNEL)?;
    rec.extend_from_slice(&(wrapped.len() as u32).to_le_bytes(), GFP_KERNEL)?;
    rec.extend_from_slice(&[0; 4], GFP_KERNEL)?;
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
    /// for a uid that gets one; nothing for the others.
    fn user_bag_designate(&self, uid: u32, handle: KeyBagHandle, secret: &[u8]) -> Result<()> {
        let Some(user) = designated_user(uid) else {
            return Ok(());
        };
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
        let path = BagPath::new(uid)?;
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
            Some(stored) => self.user_bag_load(bag.uid, &stored)?,
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
    pub(crate) fn user_bag_change_secret(
        &self,
        bags: &mut UserBags,
        uid: u32,
        old: Option<&[u8]>,
        new: &[u8],
        status: &mut i32,
    ) -> Result<()> {
        let Some(user) = designated_user(uid) else {
            return Err(crate::key::errno::opnotsupp());
        };
        let special = user.special_handle();
        let bag = bags.find(uid).ok_or(EBADF)?;
        let stored = read(uid)?.ok_or_else(crate::key::errno::nokey)?;
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
            Some(fresh) => BagPath::new(uid).and_then(|path| write(&path, uid, &stored.uuid, new, &fresh)),
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
        dev_info!(self.dev, "sep-key: uid {}'s bag secret changed\n", uid);
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
