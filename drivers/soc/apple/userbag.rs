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

use core::fmt::Write;

use kernel::prelude::*;

use crate::sks::KeyBagHandle;
use crate::store::crc16_ccitt_false;
use crate::{image, shim, LockState, Secret, SepData, SksRequest};

const MAGIC: [u8; 16] = *b"TANABOTA-SEPBAG1";
const VERSION: u32 = 1;

// MAGIC, u32 version, u32 uid, u32 wrapped length, u16 crc (over the whole
// record with this field zero), u16 0, the bag UUID, the secret, the bag.
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
const PATIENCE_MS: kernel::time::Msecs = 10_000;

/// The enclave's status for a handle it does not know (K0: an unloaded bag).
const STATUS_STALE_HANDLE: i8 = -2;

pub(crate) struct UserBag {
    uid: u32,
    handle: Option<KeyBagHandle>,
    files: u32,
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
    if !(HEADER + 1..=HEADER + MAX_WRAPPED).contains(&size) {
        return Err(crate::key::errno::uclean());
    }
    // The record holds the bag's secret: wiped when dropped.
    let mut rec = Secret(KVec::new());
    rec.0.resize(size, 0, GFP_KERNEL)?;
    f.read_exact(0, &mut rec.0)?;
    let crc = u16::from_le_bytes([rec[OFF_CRC], rec[OFF_CRC + 1]]);
    if rec[..OFF_VERSION] != MAGIC
        || u32_at(&rec, OFF_VERSION) != VERSION
        || u32_at(&rec, OFF_UID) != uid
        || u32_at(&rec, OFF_LEN) as usize != size - HEADER
        || crc != record_crc(&rec)
    {
        return Err(crate::key::errno::uclean());
    }
    let mut wrapped = KVec::new();
    wrapped.extend_from_slice(&rec[HEADER..], GFP_KERNEL)?;
    let mut secret = KVec::new();
    secret.extend_from_slice(&rec[OFF_SECRET..HEADER], GFP_KERNEL)?;
    Ok(Some(StoredBag {
        wrapped,
        secret: Secret(secret),
    }))
}

pub(crate) fn stored(uid: u32) -> bool {
    matches!(read(uid), Ok(Some(_)))
}

fn write(
    f: &shim::StoreFile,
    uid: u32,
    uuid: &[u8; UUID_LEN],
    secret: &[u8],
    wrapped: &[u8],
) -> Result<()> {
    if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED || secret.len() != crate::SKS_SECRET_LEN
    {
        return Err(EINVAL);
    }
    let mut rec = Secret(KVec::new());
    let rec = &mut rec.0;
    rec.extend_from_slice(&MAGIC, GFP_KERNEL)?;
    rec.extend_from_slice(&VERSION.to_le_bytes(), GFP_KERNEL)?;
    rec.extend_from_slice(&uid.to_le_bytes(), GFP_KERNEL)?;
    rec.extend_from_slice(&(wrapped.len() as u32).to_le_bytes(), GFP_KERNEL)?;
    rec.extend_from_slice(&[0; 4], GFP_KERNEL)?;
    rec.extend_from_slice(uuid, GFP_KERNEL)?;
    rec.extend_from_slice(secret, GFP_KERNEL)?;
    rec.extend_from_slice(wrapped, GFP_KERNEL)?;
    let crc = record_crc(rec);
    rec[OFF_CRC..OFF_CRC + 2].copy_from_slice(&crc.to_le_bytes());
    f.write_all(0, rec)?;
    f.sync()
}

/// What the enclave answered an operation on the user's bag.
pub(crate) struct OpReply {
    pub(crate) status: i8,
    pub(crate) body: KVec<u8>,
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
        if let Err(e) = self.user_bag_unlock(handle, &stored.secret) {
            let _ = self.sks_send_patient(self.sks_req_unload_keybag(handle), PATIENCE_MS);
            return Err(e);
        }
        Ok(handle)
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
        if let Err(e) = write(&file, uid, &uuid, &secret, &wrapped) {
            dev_err!(self.dev, "sep-key: storing uid {}'s bag failed: {:?}\n", uid, e);
            let _ = self.sks_send_patient(self.sks_req_unload_keybag(handle), PATIENCE_MS);
            return Err(e);
        }
        dev_info!(self.dev, "sep-key: created the keybag of uid {}\n", uid);
        if let Err(e) = self.user_bag_unlock(handle, &secret) {
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
                .sks_send_patient(self.sks_req_refkey(handle.value(), der), PATIENCE_MS)
                .ok_or(EIO)?;
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
