// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! `/dev/sep-key`: the enclave's key store for userspace, keys without access
//! control (`sep-key.h`).
//!
//! A key is the enclave's ref key, the stored set `{rk={..}}` a create answers:
//! the wrapped private key, the public key, the type. The enclave keeps no state
//! per key; every operation sends the set back as `rk` (tanabota HSM H1, H2), on
//! the caller's own keybag ([`crate::userbag`]). The blob is checked here before
//! any operation, so nothing unparsed reaches the enclave.
//!
//! What the enclave does with each type (H2, K0, all verified offline):
//! - `osgn`: P-256/P-384 ECDSA over `d` as the digest (a longer one is cut to
//!   the curve's size), DER out; Ed25519 over `d` as the message, 64 B out;
//! - `ock`: raw ECDH, X25519 and P-256/P-384, the shared x out;
//! - kt 6, the attestation key (P-384), only attests (`oa`, H4b): `osgn`
//!   answers -12; `oa` answers the statement as DER (SEP_KEY_ATTEST);
//! - other ops on a type: -12.

use kernel::ioctl::{_IO, _IOR, _IOW, _IOWR};
use kernel::prelude::*;
use kernel::sync::atomic::Relaxed;
use kernel::uaccess::{UserPtr, UserSlice};

use crate::der::RefKeyValue as RV;
use crate::userbag::OpReply;
use crate::SepData;

pub(crate) const IFACE_VERSION: u32 = 4;

/// The errnos `kernel::error::code` does not carry.
pub(crate) mod errno {
    use kernel::error::Error;

    fn of(e: u32) -> Error {
        Error::from_errno(-(e as kernel::ffi::c_int))
    }

    pub(crate) fn opnotsupp() -> Error {
        of(kernel::bindings::EOPNOTSUPP)
    }

    pub(crate) fn keyrejected() -> Error {
        of(kernel::bindings::EKEYREJECTED)
    }

    pub(crate) fn nokey() -> Error {
        of(kernel::bindings::ENOKEY)
    }

    pub(crate) fn uclean() -> Error {
        of(kernel::bindings::EUCLEAN)
    }

    pub(crate) fn keyrevoked() -> Error {
        of(kernel::bindings::EKEYREVOKED)
    }
}

pub(crate) const DEVICE_NAME: &CStr = c"sep-key";
/// udev hands the seat's user the device (`uaccess`); the bags keep users apart.
pub(crate) const DEVICE_MODE: u16 = 0o600;

const BLOB_MAX: usize = 1024;
const PUB_MAX: usize = 97;
const SIG_MAX: usize = 112;
const DATA_MAX: usize = 1024;
const SECRET_MAX: usize = 48;
const NONCE_MAX: usize = 32;
const STATEMENT_MAX: usize = 4096;

const CLASS_DEFAULT: u32 = 9;

const INFO_BAG_STORED: u32 = 1;
const INFO_BAG_LOADED: u32 = 2;
const INFO_BIOMETRY: u32 = 4;
const INFO_CREDIT: u32 = 8;
const INFO_HOME_IDENTITY: u32 = 16;

const CREATE_BIOMETRY: u32 = 1;
const CREATE_PRESENCE: u32 = 2;
const PUBKEY_BIOMETRY: u32 = 1;
const PUBKEY_PRESENCE: u32 = 2;

const AUTH_WINDOW: u32 = 1;
const AUTH_WINDOW_MAX: u32 = 300;
const AUTH_HOLD_S: u32 = 30;

const AUTH_IDLE: u32 = 0;
const AUTH_PENDING: u32 = 1;
const AUTH_MATCH: u32 = 2;
const AUTH_NOMATCH: u32 = 3;
const AUTH_FAILED: u32 = 4;

/// The SEP user whose fingers gate keys, and whose designated bag (the
/// identity bag) holds them. Only that Linux uid has gated keys for now: the
/// enclave matches per SEP user, and every finger is enrolled under this one
/// (tanabota H2b U2: a SEP user of its own per uid works, the enrolment path
/// for it is not here yet).
const BIO_USER: i32 = crate::SBIO_PROBE_USER_ID;

/// SBIO 0x33: the enrolled-set id of a SEP user (`pbioc`, 16 B), the value a
/// `cbio` constraint names (H1).
const OP_SBIO_PBIOC: u16 = 0x33;
const PBIOC_LEN: usize = 16;

/// The enclave's status for an operation the key's type does not have.
const STATUS_NOT_FOR_TYPE: i8 = -12;
/// For a ref key wrapped under another bag (K0).
const STATUS_OTHER_BAG: i8 = -7;
/// For a set it cannot parse (H2: the inner rk set instead of the whole one).
const STATUS_BAD_SET: i8 = -10;
/// For a gated key without a credited context (H2b).
const STATUS_NEEDS_MATCH: i8 = -8;
/// For a gated key whose enrolled set is gone (H2b R: every finger deleted and
/// one enrolled anew).
const STATUS_SET_GONE: i8 = -9;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    X25519,
    Ed25519,
    P256,
    P384,
    /// kt 6: attests other keys, never signs or derives.
    Attest,
}

/// The types CREATE takes (AKSRefKeyType), with what each can do.
fn kind_of(kt: u32) -> Option<Kind> {
    match kt {
        1 => Some(Kind::X25519),
        3 => Some(Kind::Ed25519),
        4 | 5 => Some(Kind::P256),
        6 => Some(Kind::Attest),
        7 | 8 => Some(Kind::P384),
        _ => None,
    }
}

const TYPES: u32 = (1 << 1) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8);

impl Kind {
    fn pub_len(self) -> usize {
        match self {
            Kind::X25519 | Kind::Ed25519 => 32,
            Kind::P256 => 65,
            Kind::P384 | Kind::Attest => 97,
        }
    }

    fn signs(self) -> bool {
        !matches!(self, Kind::X25519 | Kind::Attest)
    }

    fn derives(self) -> bool {
        !matches!(self, Kind::Ed25519 | Kind::Attest)
    }
}

// The UAPI structs, for their sizes (the ioctl numbers); the ioctls work on
// byte images of them, so that the 2 KB ones never sit on the stack: never
// built, hence `dead_code`.
#[repr(C)]
#[allow(dead_code)]
struct Info {
    version: u32,
    uid: u32,
    flags: u32,
    types: u32,
    data_max: u32,
    reserved: [u32; 3],
}

#[repr(C)]
#[allow(dead_code)]
struct Create {
    head: [u32; 8],
    blob: [u8; BLOB_MAX],
    public: [u8; PUB_MAX],
    pad: [u8; 3],
}

#[repr(C)]
#[allow(dead_code)]
struct Sign {
    head: [u32; 8],
    blob: [u8; BLOB_MAX],
    data: [u8; DATA_MAX],
    sig: [u8; SIG_MAX],
}

#[repr(C)]
#[allow(dead_code)]
struct Ecdh {
    head: [u32; 8],
    blob: [u8; BLOB_MAX],
    peer: [u8; PUB_MAX],
    secret: [u8; SECRET_MAX],
    pad: [u8; 3],
}

#[repr(C)]
#[allow(dead_code)]
struct Auth {
    flags: u32,
    window_s: u32,
    reserved: [u32; 6],
}

#[repr(C)]
#[allow(dead_code)]
struct AuthPoll {
    state: u32,
    status: u32,
    guidance: u32,
    remaining_ms: u32,
    reserved: [u32; 4],
}

#[repr(C)]
#[allow(dead_code)]
struct Pubkey {
    head: [u32; 8],
    blob: [u8; BLOB_MAX],
    public: [u8; PUB_MAX],
    pad: [u8; 3],
}

#[repr(C)]
#[allow(dead_code)]
struct Attest {
    head: [u32; 8],
    attester: [u8; BLOB_MAX],
    subject: [u8; BLOB_MAX],
    nonce: [u8; NONCE_MAX],
    statement: [u8; STATEMENT_MAX],
}

#[repr(C)]
#[allow(dead_code)]
struct ChangeSecret {
    head: [u32; 8],
    old_secret: [u8; CHANGE_SECRET_MAX],
    new_secret: [u8; CHANGE_SECRET_MAX],
}

// Sizes are baked into the ioctl numbers.
static_assert!(core::mem::size_of::<Info>() == 32);
static_assert!(core::mem::size_of::<Create>() == 1156);
static_assert!(core::mem::size_of::<Sign>() == 2192);
static_assert!(core::mem::size_of::<Ecdh>() == 1204);
static_assert!(core::mem::size_of::<Pubkey>() == 1156);
static_assert!(core::mem::size_of::<Auth>() == 32);
static_assert!(core::mem::size_of::<AuthPoll>() == 32);
static_assert!(core::mem::size_of::<Attest>() == 6208);
static_assert!(core::mem::size_of::<ChangeSecret>() == 288);

const HEAD: usize = 32;

const MAGIC: u32 = 0xB2;

const IOC_GET_INFO: u32 = _IOR::<Info>(MAGIC, 0x01);
const IOC_CREATE: u32 = _IOWR::<Create>(MAGIC, 0x02);
const IOC_SIGN: u32 = _IOWR::<Sign>(MAGIC, 0x03);
const IOC_ECDH: u32 = _IOWR::<Ecdh>(MAGIC, 0x04);
const IOC_PUBKEY: u32 = _IOWR::<Pubkey>(MAGIC, 0x05);
const IOC_AUTH: u32 = _IOW::<Auth>(MAGIC, 0x06);
const IOC_AUTH_POLL: u32 = _IOR::<AuthPoll>(MAGIC, 0x07);
const IOC_AUTH_CANCEL: u32 = _IO(MAGIC, 0x08);
const IOC_ATTEST: u32 = _IOWR::<Attest>(MAGIC, 0x09);
const IOC_CHANGE_SECRET: u32 = _IOWR::<ChangeSecret>(MAGIC, 0x0a);

/// SEP_KEY_CHANGE_SECRET: the most each secret takes (a login password),
/// and where the two are.
const CHANGE_SECRET_MAX: usize = crate::userbag::SECRET_MAX;
const CHANGE_OLD_AT: usize = HEAD;
const CHANGE_NEW_AT: usize = HEAD + CHANGE_SECRET_MAX;
/// The kernel makes the new secret: random, as a bag's first one.
const CHANGE_RANDOM: u32 = 1;
/// The caller gives the old secret (else the record's).
const CHANGE_OLD: u32 = 2;
/// The new secret SEP_KEY_CHANGE_RANDOM makes.
const RANDOM_SECRET_LEN: usize = 32;

/// A struct's byte image, read from and written back to userspace. It holds
/// an ECDH secret on its way out, so it is wiped when dropped.
struct Image {
    bytes: KVec<u8>,
}

impl Drop for Image {
    fn drop(&mut self) {
        crate::image::wipe(&mut self.bytes);
    }
}

impl Image {
    fn read(user: UserPtr, len: usize) -> Result<Image> {
        let mut bytes = KVec::new();
        bytes.resize(len, 0, GFP_KERNEL)?;
        UserSlice::new(user, len).reader().read_slice(&mut bytes)?;
        Ok(Image { bytes })
    }

    fn write(&self, user: UserPtr) -> Result<()> {
        UserSlice::new(user, self.bytes.len())
            .writer()
            .write_slice(&self.bytes)
    }

    /// Head word `i`.
    fn word(&self, i: usize) -> u32 {
        let o = i * 4;
        u32::from_ne_bytes([
            self.bytes[o],
            self.bytes[o + 1],
            self.bytes[o + 2],
            self.bytes[o + 3],
        ])
    }

    fn set_word(&mut self, i: usize, v: u32) {
        self.bytes[i * 4..i * 4 + 4].copy_from_slice(&v.to_ne_bytes());
    }

    fn field(&self, off: usize, len: usize) -> &[u8] {
        &self.bytes[off..off + len]
    }

    /// Puts `src` into the field at `off` of `cap` bytes, zero after it.
    fn put(&mut self, off: usize, cap: usize, src: &[u8]) -> Result<()> {
        if src.len() > cap {
            return Err(EIO);
        }
        self.bytes[off..off + src.len()].copy_from_slice(src);
        self.bytes[off + src.len()..off + cap].fill(0);
        Ok(())
    }
}

/// The blob's type and public key, if it is a ref key of a type we take.
fn parse_blob(blob: &[u8]) -> Result<(u32, Kind, &[u8])> {
    let rk = crate::der::refkey_find(blob, b"rk").ok_or(EINVAL)?;
    let kt = crate::der::refkey_find(rk, b"kt")
        .and_then(crate::der::integer_u32)
        .ok_or(EINVAL)?;
    let kind = kind_of(kt).ok_or(EINVAL)?;
    let public = crate::der::refkey_find(rk, b"pub")
        .and_then(crate::der::octet_string_body)
        .ok_or(EINVAL)?;
    if public.len() != kind.pub_len() {
        return Err(EINVAL);
    }
    Ok((kt, kind, public))
}

/// Whether the blob carries a `cbio` constraint (created finger-gated): its
/// `ed` member holds the ACL the create answered.
fn is_finger_gated(blob: &[u8]) -> bool {
    crate::der::refkey_find(blob, b"ed").is_some_and(|ed| ed.windows(6).any(|w| w == b"\x0c\x04cbio"))
}

/// Whether the blob carries a `cpo` constraint (created finger-or-password).
fn is_presence_gated(blob: &[u8]) -> bool {
    crate::der::refkey_find(blob, b"ed").is_some_and(|ed| ed.windows(5).any(|w| w == b"\x0c\x03cpo"))
}

/// Whether an operation with the blob needs the file's credit.
fn is_gated(blob: &[u8]) -> bool {
    is_finger_gated(blob) || is_presence_gated(blob)
}

/// The blob at `HEAD`, its length in head word `len_word`.
fn blob_in(img: &Image, len_word: usize) -> Result<&[u8]> {
    blob_at(img, HEAD, len_word)
}

/// The blob at `off`, its length in head word `len_word`.
fn blob_at(img: &Image, off: usize, len_word: usize) -> Result<&[u8]> {
    let n = img.word(len_word) as usize;
    if n == 0 || n > BLOB_MAX {
        return Err(EINVAL);
    }
    Ok(img.field(off, n))
}

fn errno_of(status: i8) -> Error {
    match status {
        STATUS_NOT_FOR_TYPE => errno::opnotsupp(),
        STATUS_OTHER_BAG => errno::keyrejected(),
        STATUS_BAD_SET => EINVAL,
        STATUS_NEEDS_MATCH => EACCES,
        STATUS_SET_GONE => errno::keyrevoked(),
        _ => EIO,
    }
}

/// The blob of an operation's reply: `i32 version (0), blob`.
fn reply_blob(r: &OpReply) -> Result<&[u8]> {
    if r.status != 0 {
        return Err(errno_of(r.status));
    }
    let mut c = crate::proto::FieldCursor::new(&r.body);
    match (c.i32(), c.blob()) {
        (Some(0), Some(b)) => Ok(b),
        _ => Err(EIO),
    }
}

type Acm = [u8; crate::scrd::SCRD_ACM_HANDLE_LEN];

/// Driver-wide AUTH state (`SepData::key_auth`, taken after `bio_session`):
/// the context the running verify credits, and a finished AUTH's outcome with
/// its time, for the owner file's next poll.
pub(crate) struct KeyAuthShared {
    pub(crate) acm: Option<Acm>,
    /// (owner file, outcome, boottime, sleep epoch): one per finished, not yet
    /// polled AUTH.
    done: KVec<(u64, crate::bio::KeyAuthState, u64, u64)>,
}

impl KeyAuthShared {
    pub(crate) fn new() -> KeyAuthShared {
        KeyAuthShared { acm: None, done: KVec::new() }
    }

    fn take(&mut self, owner: u64) -> Option<(crate::bio::KeyAuthState, u64, u64)> {
        let i = self.done.iter().position(|d| d.0 == owner)?;
        let (_, state, at, epoch) = self.done.remove(i).ok()?;
        Some((state, at, epoch))
    }
}

/// Names each open file, as the owner of the session it takes.
static NEXT_FILE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Counts system sleeps: a credit is good only in the epoch it was given in,
/// so none survives a suspend. A file's own state is reached only from its
/// callbacks, so its context is destroyed at its next callback or its close.
static SLEEP_EPOCH: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// A file's AUTH: the context it made, whether its verify still runs, and the
/// credit a match gave.
#[derive(Default)]
struct AuthState {
    acm: Option<Acm>,
    /// Its verify holds the Touch ID session.
    pending: bool,
    window: bool,
    window_s: u32,
    /// The credit: until this boottime, for one op or (window) every op.
    credit_until_ns: Option<u64>,
    /// The [`SLEEP_EPOCH`] the credit was given in.
    credit_epoch: u64,
    /// The last verify's end, for AUTH_POLL after it.
    last: u32,
    last_status: u32,
}

impl AuthState {
    fn credit_left_ns(&self) -> Option<u64> {
        let until = self.credit_until_ns?;
        if self.credit_epoch != SLEEP_EPOCH.load(core::sync::atomic::Ordering::Acquire) {
            // the system slept since the match
            return None;
        }
        let now = crate::shim::boottime_ns();
        (now < until).then(|| until - now)
    }
}

/// What [`SepData::key_home_op`] does besides the home bag.
#[derive(Clone, Copy, PartialEq)]
enum Home {
    /// A create: the uid's own bag is made if it is the home and absent.
    Create,
    /// An operation on a blob that may be a legacy one of [`BIO_USER`]'s own bag.
    Legacy,
}

/// Per open file: the uid of its opener, whose bag every operation uses, and
/// its AUTH.
pub(crate) struct KeyFile {
    uid: u32,
    id: u64,
    // Every callback for a file runs under the shim's device mutex
    // (key_shim.c), so one at a time: that is the only access.
    auth: core::cell::UnsafeCell<AuthState>,
}

impl KeyFile {
    fn new(uid: u32) -> KeyFile {
        KeyFile {
            uid,
            id: NEXT_FILE.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
            auth: core::cell::UnsafeCell::new(AuthState::default()),
        }
    }

    /// # Safety
    /// Only from a shim callback for this file (they are serialised), and the
    /// reference must not outlive it.
    #[allow(clippy::mut_from_ref)]
    unsafe fn auth(&self) -> &mut AuthState {
        // SAFETY: per the contract: one callback at a time, see the field.
        unsafe { &mut *self.auth.get() }
    }
}

impl SepData {
    fn key_get_info(&self, file: &KeyFile, user: UserPtr) -> Result<()> {
        let mut flags = 0;
        if self.key_home_identity(file)? {
            // stored, and loaded per operation only
            flags |= INFO_HOME_IDENTITY | INFO_BAG_STORED;
        } else {
            if crate::userbag::stored(file.uid) {
                flags |= INFO_BAG_STORED;
            }
            if self.user_bags.lock().loaded(file.uid) {
                flags |= INFO_BAG_LOADED;
            }
        }
        if self.key_bio_ready(file) {
            flags |= INFO_BIOMETRY;
        }
        // SAFETY: a shim callback for this file.
        if unsafe { file.auth() }.credit_left_ns().is_some() {
            flags |= INFO_CREDIT;
        }
        let mut img = Image {
            bytes: KVec::new(),
        };
        img.bytes.resize(core::mem::size_of::<Info>(), 0, GFP_KERNEL)?;
        img.set_word(0, IFACE_VERSION);
        img.set_word(1, file.uid);
        img.set_word(2, flags);
        img.set_word(3, TYPES);
        img.set_word(4, DATA_MAX as u32);
        img.write(user)
    }

    fn key_create(&self, file: &KeyFile, img: &mut Image) -> Result<()> {
        // type, class, flags, sep_status, blob_len, pub_len
        let kt = img.word(0);
        let class = match img.word(1) {
            0 => CLASS_DEFAULT,
            CLASS_DEFAULT => CLASS_DEFAULT,
            _ => return Err(EINVAL),
        };
        let flags = img.word(2);
        let Some(kind) = kind_of(kt) else {
            return Err(EINVAL);
        };
        // an attestation key is never gated
        if !matches!(flags, 0 | CREATE_BIOMETRY | CREATE_PRESENCE) || (kind == Kind::Attest && flags != 0) {
            return Err(EINVAL);
        }
        let r = if flags != 0 {
            // On the bag designated to the fingers' SEP user: an undesignated
            // user bag answers -9 to a gated key whatever the match (H2b P3.0).
            // A finger-or-password key goes there too: its password half is
            // that bag's secret (VERIFY_SECRET on -uid, U-B card 3).
            if !self.key_bio_ready(file) {
                return Err(errno::opnotsupp());
            }
            let ed = if flags == CREATE_PRESENCE { Self::key_presence_ed()? } else { self.key_gated_ed()? };
            let der = crate::der::encode_refkey_set(&[
                (b"bc", RV::Integer(class)),
                (b"ed", RV::Der(&ed)),
                (b"kt", RV::Integer(kt)),
                (b"o", RV::Utf8(b"oc")),
            ])?;
            self.key_identity_op(&der, &[])?
        } else {
            let der = crate::der::encode_refkey_set(&[
                (b"bc", RV::Integer(class)),
                (b"kt", RV::Integer(kt)),
                (b"o", RV::Utf8(b"oc")),
            ])?;
            self.key_home_op(file, &der, &[], Home::Create)?
        };
        img.set_word(3, r.status as i32 as u32);
        let blob = reply_blob(&r)?;
        let (got, _kind, public) = parse_blob(blob).map_err(|_| EIO)?;
        if got != kt || blob.len() > BLOB_MAX {
            return Err(EIO);
        }
        img.put(HEAD, BLOB_MAX, blob)?;
        img.put(HEAD + BLOB_MAX, PUB_MAX, public)?;
        img.set_word(4, blob.len() as u32);
        img.set_word(5, public.len() as u32);
        Ok(())
    }

    fn key_sign(&self, file: &KeyFile, img: &mut Image) -> Result<()> {
        // blob_len, data_len, sig_len, sep_status
        let blob = blob_in(img, 0)?;
        let (_kt, kind, public) = parse_blob(blob)?;
        if !kind.signs() {
            return Err(errno::opnotsupp());
        }
        let n = img.word(1) as usize;
        if n == 0 || n > DATA_MAX {
            return Err(EINVAL);
        }
        let data = img.field(HEAD + BLOB_MAX, n);
        let r = if is_gated(blob) {
            let acm = self.key_credit(file)?;
            let der = crate::der::encode_refkey_set(&[
                (b"acmh", RV::Octets(&acm)),
                (b"d", RV::Octets(data)),
                (b"o", RV::Utf8(b"osgn")),
                (b"rk", RV::Der(blob)),
            ])?;
            // spent also when the reply is lost after the request went out
            let r = self.key_identity_op(&der, &[public]);
            self.key_credit_used(file, r.as_ref().map_or(-1, |r| r.status));
            r?
        } else {
            let der = crate::der::encode_refkey_set(&[
                (b"d", RV::Octets(data)),
                (b"o", RV::Utf8(b"osgn")),
                (b"rk", RV::Der(blob)),
            ])?;
            self.key_home_op(file, &der, &[public], Home::Legacy)?
        };
        img.set_word(3, r.status as i32 as u32);
        let sig = reply_blob(&r).and_then(|b| crate::der::octet_string_body(b).ok_or(EIO))?;
        if sig.is_empty() || (kind == Kind::Ed25519 && sig.len() != 64) {
            return Err(EIO);
        }
        let mut copy = KVec::new();
        copy.extend_from_slice(sig, GFP_KERNEL)?;
        img.put(HEAD + BLOB_MAX + DATA_MAX, SIG_MAX, &copy)?;
        img.set_word(2, copy.len() as u32);
        Ok(())
    }

    fn key_ecdh(&self, file: &KeyFile, img: &mut Image) -> Result<()> {
        // blob_len, peer_len, secret_len, sep_status
        let blob = blob_in(img, 0)?;
        let (_kt, kind, public) = parse_blob(blob)?;
        if !kind.derives() {
            return Err(errno::opnotsupp());
        }
        let n = img.word(1) as usize;
        if n != kind.pub_len() {
            return Err(EINVAL);
        }
        let peer = img.field(HEAD + BLOB_MAX, n);
        let r = if is_gated(blob) {
            let acm = self.key_credit(file)?;
            let der = crate::der::encode_refkey_set(&[
                (b"acmh", RV::Octets(&acm)),
                (b"o", RV::Utf8(b"ock")),
                (b"pub", RV::Octets(peer)),
                (b"rk", RV::Der(blob)),
            ])?;
            // spent also when the reply is lost after the request went out
            let r = self.key_identity_op(&der, &[public]);
            self.key_credit_used(file, r.as_ref().map_or(-1, |r| r.status));
            r?
        } else {
            let der = crate::der::encode_refkey_set(&[
                (b"o", RV::Utf8(b"ock")),
                (b"pub", RV::Octets(peer)),
                (b"rk", RV::Der(blob)),
            ])?;
            self.key_home_op(file, &der, &[public], Home::Legacy)?
        };
        img.set_word(3, r.status as i32 as u32);
        let secret = reply_blob(&r).and_then(|b| crate::der::octet_string_body(b).ok_or(EIO))?;
        let want = if kind == Kind::P384 { 48 } else { 32 };
        if secret.len() != want {
            return Err(EIO);
        }
        let mut copy = crate::Secret(KVec::new());
        copy.0.extend_from_slice(secret, GFP_KERNEL)?;
        img.put(HEAD + BLOB_MAX + PUB_MAX, SECRET_MAX, &copy)?;
        img.set_word(2, copy.len() as u32);
        Ok(())
    }

    fn key_pubkey(&self, img: &mut Image) -> Result<()> {
        // blob_len, type, pub_len
        let blob = blob_in(img, 0)?;
        let (kt, _kind, public) = parse_blob(blob)?;
        let gated = if is_finger_gated(blob) {
            PUBKEY_BIOMETRY
        } else if is_presence_gated(blob) {
            PUBKEY_PRESENCE
        } else {
            0
        };
        let mut copy = KVec::new();
        copy.extend_from_slice(public, GFP_KERNEL)?;
        img.put(HEAD + BLOB_MAX, PUB_MAX, &copy)?;
        img.set_word(1, kt);
        img.set_word(2, copy.len() as u32);
        img.set_word(3, gated);
        Ok(())
    }

    fn key_attest(&self, file: &KeyFile, img: &mut Image) -> Result<()> {
        // attester_len, subject_len, nonce_len, sep_status, statement_len,
        // reserved[3]
        if img.word(5) != 0 || img.word(6) != 0 || img.word(7) != 0 {
            return Err(EINVAL);
        }
        let attester = blob_at(img, HEAD, 0)?;
        let subject = blob_at(img, HEAD + BLOB_MAX, 1)?;
        let (_kt, kind, attester_pub) = parse_blob(attester)?;
        if kind != Kind::Attest {
            return Err(errno::opnotsupp());
        }
        let (_kt, subject_kind, subject_pub) = parse_blob(subject)?;
        if subject_kind == Kind::X25519 {
            // no proof of possession in its statement (libaks), never seen
            return Err(errno::opnotsupp());
        }
        let n = img.word(2) as usize;
        if n > NONCE_MAX {
            return Err(EINVAL);
        }
        let nonce = img.field(HEAD + 2 * BLOB_MAX, n);
        let der = {
            let d = crate::der::encode_refkey_set(&[(b"rk", RV::Der(subject))])?;
            let mut items = KVec::new();
            items.push((&b"d"[..], RV::Der(&d)), GFP_KERNEL)?;
            items.push((&b"o"[..], RV::Utf8(b"oa")), GFP_KERNEL)?;
            items.push((&b"rk"[..], RV::Der(attester)), GFP_KERNEL)?;
            if !nonce.is_empty() {
                items.push((&b"salt"[..], RV::Octets(nonce)), GFP_KERNEL)?;
            }
            crate::der::encode_refkey_set(&items)?
        };
        // Both keys live in the caller's home bag (a gated subject's ACL has
        // `oa=true`, H4b-4: no credit); the enclave refuses a mix (-7). A
        // legacy pair in uid 1000's own bag is tried there too.
        let r = if is_gated(subject) {
            if file.uid as i32 != BIO_USER {
                return Err(errno::opnotsupp());
            }
            self.key_identity_op(&der, &[attester_pub, subject_pub])?
        } else {
            self.key_home_op(file, &der, &[attester_pub, subject_pub], Home::Legacy)?
        };
        img.set_word(3, r.status as i32 as u32);
        let statement = reply_blob(&r)?;
        if statement.len() > STATEMENT_MAX || !crate::der::is_one_sequence(statement) {
            return Err(EIO);
        }
        img.put(HEAD + 2 * BLOB_MAX + NONCE_MAX, STATEMENT_MAX, statement)?;
        img.set_word(4, statement.len() as u32);
        Ok(())
    }

    /// True when the caller must queue the verify work item (AUTH).
    fn key_ioctl(&self, file: &KeyFile, cmd: u32, arg: usize) -> Result<bool> {
        let user = UserPtr::from_addr(arg);
        let (len, run): (usize, fn(&SepData, &KeyFile, &mut Image) -> Result<()>) = match cmd {
            IOC_GET_INFO => return self.key_get_info(file, user).map(|()| false),
            IOC_AUTH_POLL => return self.key_auth_poll(file, user).map(|()| false),
            IOC_AUTH_CANCEL => return self.key_auth_cancel(file).map(|()| false),
            IOC_AUTH => {
                if !self.sks_ready() {
                    return Err(ENODEV);
                }
                let img = Image::read(user, core::mem::size_of::<Auth>())?;
                return self.key_auth_start(file, &img);
            }
            IOC_CREATE => (core::mem::size_of::<Create>(), |s, f, i| s.key_create(f, i)),
            IOC_SIGN => (core::mem::size_of::<Sign>(), |s, f, i| s.key_sign(f, i)),
            IOC_ECDH => (core::mem::size_of::<Ecdh>(), |s, f, i| s.key_ecdh(f, i)),
            IOC_PUBKEY => (core::mem::size_of::<Pubkey>(), |s, _, i| s.key_pubkey(i)),
            IOC_ATTEST => (core::mem::size_of::<Attest>(), |s, f, i| s.key_attest(f, i)),
            IOC_CHANGE_SECRET => (core::mem::size_of::<ChangeSecret>(), |s, f, i| s.key_change_secret(f, i)),
            _ => return Err(ENOTTY),
        };
        if !self.sks_ready() {
            return Err(ENODEV);
        }
        let mut img = Image::read(user, len)?;
        let done = run(self, file, &mut img);
        // Back also on a refusal: sep_status says what the enclave answered.
        img.write(user)?;
        done.map(|()| false)
    }

    pub(crate) fn register_key(&self) -> Result<()> {
        if self.profile.key_store != crate::profile::KeyStore::Variant5 {
            // The only key store K0 measured; the 13.5 dialect differs.
            return Ok(());
        }
        let mut guard = self.key_dev.lock();
        if guard.is_some() {
            return Ok(());
        }
        let ctx = core::ptr::from_ref(self).cast_mut().cast::<c_void>();
        // SAFETY: as for `register_bio`: `ctx` is this `SepData`, kept alive
        // by the driver's `Arc`; `remove()` drops the registration first, and
        // the shim clears its context under the lock every callback takes.
        let dev = unsafe { sep_key_register(DEVICE_NAME.as_char_ptr(), DEVICE_MODE, ctx, key_open, key_release, key_ioctl) };
        if dev.is_null() {
            return Err(ENODEV);
        }
        *guard = Some(KeyChardev { dev });
        dev_info!(self.dev, "sep-key: /dev/{} up\n", DEVICE_NAME);
        Ok(())
    }
}

// Finger-gated keys (H2b): the context, the verify that credits it, and the
// operations on the identity bag.
impl SepData {
    fn key_acm_create(&self) -> Result<Acm> {
        if !self.scrd_ready() {
            return Err(ENODEV);
        }
        // No SCRD INITIALIZE here: it would end the match credential the
        // attach set up (H2b U2: matches then answer 0x16).
        let (st, out) = self
            .scrd_command(&crate::scrd::scrd_context_create_tracked(BIO_USER))
            .ok_or(EIO)?;
        if st != 0 || out.len() < crate::scrd::SCRD_ACM_HANDLE_LEN {
            dev_warn!(self.dev, "sep-key: context create: status {}, {} B\n", st, out.len());
            return Err(EIO);
        }
        let mut acm = [0u8; crate::scrd::SCRD_ACM_HANDLE_LEN];
        acm.copy_from_slice(&out[..crate::scrd::SCRD_ACM_HANDLE_LEN]);
        let (st, _) = self
            .scrd_command(&crate::scrd::scrd_context_externalize(&acm))
            .ok_or(EIO)?;
        if st != 0 {
            dev_warn!(self.dev, "sep-key: context externalize: status {}\n", st);
            let _ = self.scrd_command(&crate::scrd::scrd_context_destroy(&acm));
            return Err(EIO);
        }
        Ok(acm)
    }

    /// Ends the file's context and credit (the verify, if any, is not touched).
    fn key_auth_forget(&self, auth: &mut AuthState) {
        auth.credit_until_ns = None;
        if let Some(acm) = auth.acm.take() {
            let _ = self.scrd_command(&crate::scrd::scrd_context_destroy(&acm));
        }
    }

    /// A /dev/sep-key AUTH's verify ended (under `bio_session`): give the
    /// session back and keep the outcome, with when it came, for the owner's
    /// poll. A client that never polls cannot hold the sensor.
    pub(crate) fn key_auth_settle(&self, session: &mut crate::bio::Session) {
        let Some(owner) = crate::bio::key_auth_owner(session) else {
            return;
        };
        let state = crate::bio::key_auth_poll(session);
        if matches!(state, crate::bio::KeyAuthState::Pending(_)) {
            return;
        }
        crate::bio::release(session);
        let mut shared = self.key_auth.lock();
        shared.acm = None;
        let _ = shared.take(owner);
        // On no memory the outcome is lost: the owner's poll reports a failure.
        let epoch = SLEEP_EPOCH.load(core::sync::atomic::Ordering::Acquire);
        let _ = shared
            .done
            .push((owner, state, crate::shim::boottime_ns(), epoch), GFP_KERNEL);
    }

    /// The system is about to sleep (after every capture has stopped): every
    /// credit ends, those given and those of a match not yet polled, as on
    /// SEP_KEY_AUTH_CANCEL. The files' contexts go at their next callback.
    pub(crate) fn key_auth_sleep(&self) {
        let mut session = self.bio_session.lock();
        // A verify that ended unfiled is filed now, in the epoch that ends.
        self.key_auth_settle(&mut session);
        let _shared = self.key_auth.lock();
        SLEEP_EPOCH.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    }

    /// Ends the file's AUTH: a verify still running is cancelled and its
    /// session given back; a kept outcome is dropped.
    fn key_auth_abandon(&self, file: &KeyFile, auth: &mut AuthState) {
        if auth.pending {
            let woke = {
                let mut session = self.bio_session.lock();
                let ours = crate::bio::key_auth_owner(&session) == Some(file.id);
                if ours {
                    let _ = crate::bio::abort_capture(&mut session);
                    crate::bio::release(&mut session);
                }
                let mut shared = self.key_auth.lock();
                if ours {
                    shared.acm = None;
                }
                let _ = shared.take(file.id);
                ours
            };
            auth.pending = false;
            if woke {
                self.bio_wake();
            }
        }
        self.key_auth_forget(auth);
        auth.last = AUTH_IDLE;
    }

    /// Whether this uid can have gated keys. Not whether the sensor is up yet:
    /// before the first /dev/sep-bio open of a boot it is not, and create and
    /// AUTH bring Touch ID up themselves.
    fn key_bio_ready(&self, file: &KeyFile) -> bool {
        file.uid as i32 == BIO_USER && !self.touchid_failed.load(Relaxed)
    }

    /// SEP_KEY_AUTH: a fresh context and a verify that credits it. True when
    /// the caller must queue the verify work item.
    fn key_auth_start(&self, file: &KeyFile, img: &Image) -> Result<bool> {
        if self.shutting_down.load(Relaxed) {
            return Err(ENODEV);
        }
        if file.uid as i32 != BIO_USER {
            return Err(errno::opnotsupp());
        }
        let (flags, window_s) = (img.word(0), img.word(1));
        let window = flags & AUTH_WINDOW != 0;
        if flags & !AUTH_WINDOW != 0 || (window && !(1..=AUTH_WINDOW_MAX).contains(&window_s)) {
            return Err(EINVAL);
        }
        // SAFETY: a shim callback for this file.
        let auth = unsafe { file.auth() };
        if auth.pending {
            return Err(EBUSY);
        }
        self.key_auth_forget(auth);

        // The session, as an open of /dev/sep-bio takes it (and only then the
        // Touch ID activation an open does).
        {
            let mut session = self.bio_session.lock();
            self.wait_for_worker_exit(&mut session, true)?;
            if self.shutting_down.load(Relaxed) {
                return Err(ENODEV);
            }
            crate::bio::key_auth_open(&mut session, file.id, file.uid, crate::touch::current_caller())?;
        }
        let give_back = |sep: &SepData| crate::bio::release(&mut sep.bio_session.lock());
        if let Err(e) = self.prepare_bio_open() {
            give_back(self);
            return Err(e);
        }
        // A restore proof left undone is redone here, before the context: it
        // sends SCRD INITIALIZE, which would end a context made earlier. If it
        // stays undone the verify would retry it after the context: refuse.
        self.retry_restore_proof();
        if !self.templates_restored.load(Relaxed) {
            give_back(self);
            return Err(EIO);
        }
        let acm = match self.key_acm_create() {
            Ok(acm) => acm,
            Err(e) => {
                give_back(self);
                return Err(e);
            }
        };
        let begun = {
            let mut session = self.bio_session.lock();
            let index = self.bio_index.lock();
            let mut ctx = crate::bio::Context {
                session: &mut session,
                index: &index,
                sensor_present: crate::sensor::is_bound(),
                live_identity_count: None,
            };
            let r = crate::bio::key_auth_begin(&mut ctx, file.id);
            drop(index);
            match r {
                Ok(()) => {
                    let mut shared = self.key_auth.lock();
                    shared.acm = Some(acm);
                    let _ = shared.take(file.id);
                }
                Err(_) if crate::bio::key_auth_owner(&session) == Some(file.id) => {
                    crate::bio::release(&mut session)
                }
                Err(_) => {}
            }
            r
        };
        if let Err(e) = begun {
            let _ = self.scrd_command(&crate::scrd::scrd_context_destroy(&acm));
            return Err(e);
        }
        // the sensor waits for this file's finger from now
        self.touch_update();
        *auth = AuthState {
            acm: Some(acm),
            pending: true,
            window,
            window_s,
            credit_until_ns: None,
            credit_epoch: 0,
            last: AUTH_PENDING,
            last_status: 0,
        };
        Ok(true)
    }

    fn key_auth_poll(&self, file: &KeyFile, user: UserPtr) -> Result<()> {
        // SAFETY: a shim callback for this file.
        let auth = unsafe { file.auth() };
        let mut guidance = 0u32;
        if auth.pending {
            let outcome = {
                let mut session = self.bio_session.lock();
                if crate::bio::key_auth_owner(&session) == Some(file.id) {
                    match crate::bio::key_auth_poll(&session) {
                        crate::bio::KeyAuthState::Pending(g) => guidance = g as u32,
                        // ended without the worker filing it (a suspend)
                        _ => self.key_auth_settle(&mut session),
                    }
                }
                let mut shared = self.key_auth.lock();
                match shared.take(file.id) {
                    Some(kept) => Some(kept),
                    None if crate::bio::key_auth_owner(&session) != Some(file.id) => {
                        // neither running nor kept: lost (a driver reset)
                        Some((crate::bio::KeyAuthState::Failed(0), 0, 0))
                    }
                    None => None,
                }
            };
            if let Some((state, at, epoch)) = outcome {
                auth.pending = false;
                self.bio_wake();
                match state {
                    crate::bio::KeyAuthState::Matched => {
                        // from the match, not from this poll
                        let s = if auth.window { auth.window_s } else { AUTH_HOLD_S };
                        auth.credit_until_ns = Some(at + u64::from(s) * 1_000_000_000);
                        auth.credit_epoch = epoch;
                        auth.last = AUTH_MATCH;
                    }
                    crate::bio::KeyAuthState::NoMatch => {
                        self.key_auth_forget(auth);
                        auth.last = AUTH_NOMATCH;
                    }
                    crate::bio::KeyAuthState::Failed(_) | crate::bio::KeyAuthState::Pending(_) => {
                        let status = if let crate::bio::KeyAuthState::Failed(st) = state { st } else { 0 };
                        self.key_auth_forget(auth);
                        auth.last = AUTH_FAILED;
                        auth.last_status = status;
                    }
                }
            }
        }
        let mut img = Image { bytes: KVec::new() };
        img.bytes.resize(core::mem::size_of::<AuthPoll>(), 0, GFP_KERNEL)?;
        let mut state = auth.last;
        let mut remaining = 0u32;
        if state == AUTH_MATCH {
            match auth.credit_left_ns() {
                Some(ns) => remaining = (ns / 1_000_000).min(u64::from(u32::MAX)) as u32,
                None => {
                    // used up or expired
                    self.key_auth_forget(auth);
                    auth.last = AUTH_IDLE;
                    state = AUTH_IDLE;
                }
            }
        }
        img.set_word(0, state);
        img.set_word(1, if state == AUTH_FAILED { auth.last_status } else { 0 });
        img.set_word(2, guidance);
        img.set_word(3, remaining);
        img.write(user)
    }

    fn key_auth_cancel(&self, file: &KeyFile) -> Result<()> {
        // SAFETY: a shim callback for this file.
        let auth = unsafe { file.auth() };
        let had = auth.pending || auth.acm.is_some();
        self.key_auth_abandon(file, auth);
        if had { Ok(()) } else { Err(ENOENT) }
    }

    /// The file is closing: no verify or context outlives it.
    fn key_auth_close(&self, file: &KeyFile) {
        let _ = self.key_auth_cancel(file);
    }

    /// The credited context for an operation on a gated key, or EACCES.
    fn key_credit(&self, file: &KeyFile) -> Result<Acm> {
        if file.uid as i32 != BIO_USER {
            return Err(errno::opnotsupp());
        }
        // SAFETY: a shim callback for this file.
        let auth = unsafe { file.auth() };
        match (auth.acm, auth.credit_left_ns()) {
            (Some(acm), Some(_)) if !auth.pending => Ok(acm),
            _ => {
                if !auth.pending {
                    self.key_auth_forget(auth);
                }
                Err(EACCES)
            }
        }
    }

    /// After an operation with the credit: a one-op credit is spent, and a
    /// refused one is gone either way.
    fn key_credit_used(&self, file: &KeyFile, status: i8) {
        // SAFETY: a shim callback for this file.
        let auth = unsafe { file.auth() };
        if !auth.window || status != 0 {
            self.key_auth_forget(auth);
            auth.last = AUTH_IDLE;
        }
    }

    /// One PERFORM_OPERATION on the identity bag (designated to [`BIO_USER`]),
    /// loaded and unlocked for it and unloaded after, as the machine ref key's.
    /// `rk_pubs` are the public keys of the ref keys the operation sends:
    /// never the machine ref key's, which lives in this bag too and seals the
    /// trusted keys (an `ock` with it would hand out their wrapping secret).
    /// The gate in the blob's `ed` is the caller's to claim, so it is no guard:
    /// the enclave's own binding of the ACL is (H2b R5; the bench's
    /// stripped-`ed` negative).
    fn key_identity_op(&self, der: &[u8], rk_pubs: &[&[u8]]) -> Result<OpReply> {
        self.key_identity_try(der, rk_pubs)?.ok_or(ENODEV)
    }

    /// [`Self::key_identity_op`], or `None` when there is no identity bag:
    /// one read of its record, under its lock, decides and serves the op.
    fn key_identity_try(&self, der: &[u8], rk_pubs: &[&[u8]]) -> Result<Option<OpReply>> {
        for public in rk_pubs {
            if self.is_machine_refkey(public)? {
                dev_dbg!(self.dev, "sep-key: refused an operation with the machine ref key\n");
                return Err(EPERM);
            }
        }
        let _bag = self.identity_bag_lock.lock();
        let crate::keybag::State::Present(stored) = crate::keybag::read(crate::keybag::Slot::Identity)? else {
            return Ok(None);
        };
        // as patient as the user bags: these are a user's everyday keys now
        let patience = crate::userbag::PATIENCE_MS;
        let (handle, _uuid) = self.sks_recover(&stored).ok_or(EIO)?;
        let result = (|| {
            let healthy = self.sks_health_check(c"sep-key identity").ok_or(EIO)?;
            let out = self
                .sks_send_patient(
                    self.sks_req_change_lock_state(handle, crate::LockState::Unlocked, stored.secret(), healthy),
                    patience,
                )
                .ok_or(EIO)?;
            if out.reply.status != 0 {
                return Err(EIO);
            }
            let out = self
                .sks_send_patient(self.sks_req_refkey(handle.value(), der), patience)
                .ok_or(EIO)?;
            let mut body = KVec::new();
            if out.reply.status == 0 {
                let b = self
                    .sks_report_response(crate::sks::SKS_PERFORM_OP_NAME, &out)
                    .ok_or(EIO)?;
                body.extend_from_slice(b, GFP_KERNEL)?;
            }
            Ok(OpReply { status: out.reply.status, body })
        })();
        let _ = self.sks_send_patient(self.sks_req_unload_keybag(handle), patience);
        result.map(Some)
    }

    /// SEP_KEY_CHANGE_SECRET: a new secret for the caller's home bag, its keys
    /// and EK kept (tanabota U-J, U-K): the identity bag for [`BIO_USER`]
    /// (designated to -1000), a uid's own bag (designated to -uid when loaded,
    /// userbag.rs) for the others. uid 0 and 1..9 have no designated bag:
    /// EOPNOTSUPP. Both secrets are wiped from the image before it goes back.
    fn key_change_secret(&self, file: &KeyFile, img: &mut Image) -> Result<()> {
        // flags, sep_status, old_len, new_len, reserved[4]
        let (flags, old_len, new_len) = (img.word(0), img.word(2) as usize, img.word(3) as usize);
        let random = flags & CHANGE_RANDOM != 0;
        let given_old = flags & CHANGE_OLD != 0;
        let bad = flags & !(CHANGE_RANDOM | CHANGE_OLD) != 0
            || old_len > CHANGE_SECRET_MAX
            || new_len > CHANGE_SECRET_MAX
            || random == (new_len != 0)
            || given_old == (old_len == 0)
            || (4..8).any(|i| img.word(i) != 0);
        let mut old = crate::Secret(KVec::new());
        let mut new = crate::Secret(KVec::new());
        if !bad {
            old.0.extend_from_slice(img.field(CHANGE_OLD_AT, old_len), GFP_KERNEL)?;
            new.0.extend_from_slice(img.field(CHANGE_NEW_AT, new_len), GFP_KERNEL)?;
        }
        img.put(CHANGE_OLD_AT, CHANGE_SECRET_MAX, &[])?;
        img.put(CHANGE_NEW_AT, CHANGE_SECRET_MAX, &[])?;
        if bad {
            return Err(EINVAL);
        }
        if random {
            new.0.resize(RANDOM_SECRET_LEN, 0, GFP_KERNEL)?;
            crate::shim::random_bytes(&mut new.0)?;
        }
        let old = given_old.then_some(&old.0[..]);
        let mut status = 0;
        let r = if file.uid as i32 == BIO_USER {
            self.key_identity_change_secret(old, &new, &mut status)
        } else {
            self.user_bag_change_secret(&mut self.user_bags.lock(), file.uid, old, &new, &mut status)
        };
        img.set_word(1, status as u32);
        r
    }

    /// [`Self::key_change_secret`] on the identity bag: under its lock, load
    /// it, designate it to [`BIO_USER`] unless the Touch ID bring-up did, op
    /// 0x07 on -1000, COPY_KEYBAG on -1000 and one atomic replace of the
    /// record. Every other user of the secret reads the record per use; the
    /// enrolment path's copy is updated here.
    fn key_identity_change_secret(&self, old: Option<&[u8]>, new: &[u8], status: &mut i32) -> Result<()> {
        let user = crate::sks::DesignateUser::new(BIO_USER).ok_or(EINVAL)?;
        let special = user.special_handle();
        let patience = crate::userbag::PATIENCE_MS;

        let _bag = self.identity_bag_lock.lock();
        let crate::keybag::State::Present(stored) = crate::keybag::read(crate::keybag::Slot::Identity)? else {
            // before the first enrolment uid 1000's keys live in its own bag,
            // never designated (-1000 is the identity bag's to be)
            return Err(errno::opnotsupp());
        };
        let (handle, _uuid) = self.sks_recover(&stored).ok_or(EIO)?;
        let result = (|| {
            if !self.keybag_designated.load(Relaxed) {
                let d = crate::sks::Designation::new(handle, user);
                let out = self.sks_send_patient(self.sks_req_designate(&d, stored.secret()), patience).ok_or(EIO)?;
                if out.reply.status != 0 {
                    *status = out.reply.status as i32;
                    return Err(errno_of(out.reply.status));
                }
            }
            let out = self
                .sks_send_patient(self.sks_req_change_secret(special, old.unwrap_or(stored.secret()), new), patience)
                .ok_or(EIO)?;
            *status = out.reply.status as i32;
            if out.reply.status != 0 {
                return Err(EACCES);
            }
            // From here the enclave holds the new secret. If the record is not
            // rewritten, the old one still opens with the old secret (no
            // generation in the enclave, U-J), so ops keep working, and the
            // next boot loads the old copy: the change is lost, not the bag.
            let fresh = self
                .sks_send_patient(self.sks_req_copy_keybag_special(special), patience)
                .and_then(|out| self.wrapped_from_copy_reply(&out, c"the identity bag after its change"));
            let written = match fresh {
                Some(fresh) => crate::keybag::replace_bag_and_secret(crate::keybag::Slot::Identity, &fresh, new),
                None => Err(EIO),
            };
            if let Err(e) = written {
                dev_err!(
                    self.dev,
                    "sep-key: the identity bag's secret changed in the enclave but its record was not rewritten ({:?}); the old record stays valid until reboot loads it\n",
                    e
                );
                return Err(EIO);
            }
            self.sks_update_enrolment_secret(special, new)?;
            dev_info!(self.dev, "sep-key: the identity bag's secret changed\n");
            Ok(())
        })();
        let _ = self.sks_send_patient(self.sks_req_unload_keybag(handle), patience);
        result
    }

    /// Whether the caller's keys live in the identity bag: [`BIO_USER`]'s,
    /// once the bag exists (before the first enrolment they live in its own).
    fn key_home_identity(&self, file: &KeyFile) -> Result<bool> {
        if file.uid as i32 != BIO_USER {
            return Ok(false);
        }
        let _bag = self.identity_bag_lock.lock();
        Ok(matches!(
            crate::keybag::read(crate::keybag::Slot::Identity)?,
            crate::keybag::State::Present(_)
        ))
    }

    /// One ungated operation on the caller's home bag (macOS's one bag per
    /// user): the identity bag for [`BIO_USER`] once it exists, else the
    /// uid's own bag (made by a create). With [`Home::Legacy`], a blob the
    /// identity bag calls another bag's (-7) is tried once on [`BIO_USER`]'s
    /// own bag, if stored: its keys from before interface 4.
    ///
    /// The bag is chosen by the same read that serves the op. An identity bag
    /// made between that read and a create on the own bag (an enrolment
    /// finishing meanwhile) leaves the new key there: a legacy one, working
    /// through the retry. A retry that fails keeps the -7 (its error only in
    /// the debug log); a legacy record that does not check out is its error.
    fn key_home_op(&self, file: &KeyFile, der: &[u8], rk_pubs: &[&[u8]], how: Home) -> Result<OpReply> {
        let own = |sep: &SepData| sep.user_bag_op(&mut sep.user_bags.lock(), file.uid, how == Home::Create, der);
        if file.uid as i32 != BIO_USER {
            return own(self);
        }
        let r = match self.key_identity_try(der, rk_pubs)? {
            Some(r) => r,
            // uid 1000's home bag is made on its first create like any uid's,
            // as the identity bag (keybag.rs keeps it as uid 1000's home
            // record); only keys from before interface 4 live in its own bag.
            // provision_keybag=0 (the bench's copies of m2pro's state) makes
            // none, as at the Touch ID bring-up.
            None if how == Home::Create
                && *crate::module_parameters::provision_keybag.value() != 0
                && !crate::userbag::stored_checked(file.uid)? =>
            {
                if !self.sks_provision_identity_keybag() {
                    return Err(EIO);
                }
                self.key_identity_try(der, rk_pubs)?.ok_or(EIO)?
            }
            None => return own(self),
        };
        if how != Home::Legacy || r.status != STATUS_OTHER_BAG || !crate::userbag::stored_checked(file.uid)? {
            return Ok(r);
        }
        match own(self) {
            Ok(legacy) => Ok(legacy),
            Err(e) => {
                dev_dbg!(self.dev, "sep-key: uid {}'s own bag: {:?}\n", file.uid, e);
                Ok(r)
            }
        }
    }

    /// The enrolled-set id of [`BIO_USER`] (op33).
    fn key_pbioc(&self) -> Result<[u8; PBIOC_LEN]> {
        let done = self.sbio_transfer_raw(OP_SBIO_PBIOC, c"SBIO_PBIOC", &BIO_USER.to_le_bytes())?;
        if !done.status.is_ok() || done.payload.len() < PBIOC_LEN {
            // 22 when the user has no enrolled finger (H2b h2b-1, U1)
            return Err(errno::nokey());
        }
        let mut p = [0u8; PBIOC_LEN];
        p.copy_from_slice(&done.payload[..PBIOC_LEN]);
        Ok(p)
    }

    /// The `ed` of a gated create: `{acl={ock,osgn,okd={cbio={pbioc}}, odel,oa=true}}`,
    /// macOS's any-biometry key (H1).
    fn key_gated_ed(&self) -> Result<KVec<u8>> {
        // op33 needs Touch ID up. The first activation runs holding the
        // session, as a /dev/sep-bio open does, so never alongside another.
        if !self.touchid_started.load(Relaxed) {
            {
                let mut session = self.bio_session.lock();
                self.wait_for_worker_exit(&mut session, true)?;
                crate::bio::open(&mut session)?;
            }
            let r = self.prepare_bio_open();
            crate::bio::release(&mut self.bio_session.lock());
            r?;
        }
        let pbioc = self.key_pbioc()?;
        let inner = crate::der::encode_refkey_set(&[(b"pbioc", RV::Octets(&pbioc))])?;
        let cbio = crate::der::encode_refkey_set(&[(b"cbio", RV::Der(&inner))])?;
        const TRUE: &[u8] = &[0x01, 0x01, 0x01];
        let acl = crate::der::encode_refkey_set(&[
            (b"oa", RV::Der(TRUE)),
            (b"ock", RV::Der(&cbio)),
            (b"odel", RV::Der(TRUE)),
            (b"okd", RV::Der(&cbio)),
            (b"osgn", RV::Der(&cbio)),
        ])?;
        crate::der::encode_refkey_set(&[(b"acl", RV::Der(&acl))])
    }

    /// The `ed` of a finger-or-password create: `{acl={ock,osgn,okd={cpo=
    /// "DeviceOwnerAuthentication"}, odel,oa=true}}`, macOS's
    /// `.userPresence` (H1 01588; bench U-C: a match credits it, U-B: so does
    /// a VERIFY_SECRET of the bag's secret).
    fn key_presence_ed() -> Result<KVec<u8>> {
        let cpo = crate::der::encode_refkey_set(&[(b"cpo", RV::Utf8(b"DeviceOwnerAuthentication"))])?;
        const TRUE: &[u8] = &[0x01, 0x01, 0x01];
        let acl = crate::der::encode_refkey_set(&[
            (b"oa", RV::Der(TRUE)),
            (b"ock", RV::Der(&cpo)),
            (b"odel", RV::Der(TRUE)),
            (b"okd", RV::Der(&cpo)),
            (b"osgn", RV::Der(&cpo)),
        ])?;
        crate::der::encode_refkey_set(&[(b"acl", RV::Der(&acl))])
    }
}

extern "C" {
    fn sep_key_register(
        name: *const c_char,
        mode: u16,
        ctx: *mut c_void,
        f_open: unsafe extern "C" fn(*mut c_void, u32, *mut c_int) -> *mut c_void,
        f_release: unsafe extern "C" fn(*mut c_void, *mut c_void),
        f_ioctl: unsafe extern "C" fn(*mut c_void, *mut c_void, c_uint, c_ulong) -> c_long,
    ) -> *mut c_void;
    fn sep_key_unregister(dev: *mut c_void);
}

/// The registered `/dev/sep-key`.
///
/// # Invariants
/// `dev` is a live registration from `sep_key_register`.
pub(crate) struct KeyChardev {
    dev: *mut c_void,
}

// SAFETY: the registration has no thread affinity; the shim locks internally.
unsafe impl Send for KeyChardev {}

impl Drop for KeyChardev {
    fn drop(&mut self) {
        // SAFETY: `dev` is live per the type invariant and not used again. Once
        // this returns no callback sees the context; open files only release.
        unsafe { sep_key_unregister(self.dev) };
    }
}

/// # Safety
///
/// Each is called only by `key_shim.c`: `ctx` is the `*const SepData` handed
/// to `sep_key_register`, valid while registered (`release` gets NULL after
/// that), and `fctx` a pointer `key_open` returned and `key_release` not yet
/// freed.
unsafe extern "C" fn key_open(ctx: *mut c_void, uid: u32, err: *mut c_int) -> *mut c_void {
    // SAFETY: per the contract above.
    let this = unsafe { &*ctx.cast::<SepData>() };
    let opened = KBox::new(KeyFile::new(uid), GFP_KERNEL)
        .map_err(Error::from)
        .and_then(|f| this.user_bag_open(&mut this.user_bags.lock(), uid).map(|()| f));
    match opened {
        Ok(f) => KBox::into_raw(f).cast::<c_void>(),
        Err(e) => {
            // SAFETY: the shim passes its local.
            unsafe { *err = e.to_errno() };
            core::ptr::null_mut()
        }
    }
}

/// # Safety
unsafe extern "C" fn key_release(ctx: *mut c_void, fctx: *mut c_void) {
    // SAFETY: per the contract above: `fctx` came from `KBox::into_raw`.
    let file = unsafe { KBox::from_raw(fctx.cast::<KeyFile>()) };
    if ctx.is_null() {
        return;
    }
    // SAFETY: per the contract above.
    let this = unsafe { &*ctx.cast::<SepData>() };
    this.key_auth_close(&file);
    this.user_bag_close(&mut this.user_bags.lock(), file.uid);
}

/// # Safety
unsafe extern "C" fn key_ioctl(ctx: *mut c_void, fctx: *mut c_void, cmd: c_uint, arg: c_ulong) -> c_long {
    // SAFETY: per the contract above.
    let (this, file) = unsafe { (&*ctx.cast::<SepData>(), &*fctx.cast::<KeyFile>()) };
    match this.key_ioctl(file, cmd, arg as usize) {
        Ok(queue) => {
            if queue {
                // SAFETY: `ctx` is the pointer the driver's own `Arc<SepData>`
                // was made from, which outlives every callback (see
                // `register_key`); `ArcBorrow` takes a counted reference.
                let borrow = unsafe { kernel::sync::ArcBorrow::<SepData>::from_raw(ctx.cast::<SepData>()) };
                SepData::queue_verify(borrow.into());
            }
            0
        }
        Err(e) => e.to_errno() as c_long,
    }
}
