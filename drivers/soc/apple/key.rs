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
//! - other ops on a type: -12.

use kernel::ioctl::{_IO, _IOR, _IOW, _IOWR};
use kernel::prelude::*;
use kernel::sync::atomic::Relaxed;
use kernel::uaccess::{UserPtr, UserSlice};

use crate::der::RefKeyValue as RV;
use crate::userbag::OpReply;
use crate::SepData;

pub(crate) const IFACE_VERSION: u32 = 2;

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

const CLASS_DEFAULT: u32 = 9;

const INFO_BAG_STORED: u32 = 1;
const INFO_BAG_LOADED: u32 = 2;
const INFO_BIOMETRY: u32 = 4;
const INFO_CREDIT: u32 = 8;

const CREATE_BIOMETRY: u32 = 1;
const PUBKEY_BIOMETRY: u32 = 1;

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
}

/// The types CREATE takes (AKSRefKeyType), with what each can do.
fn kind_of(kt: u32) -> Option<Kind> {
    match kt {
        1 => Some(Kind::X25519),
        3 => Some(Kind::Ed25519),
        4 | 5 => Some(Kind::P256),
        7 | 8 => Some(Kind::P384),
        _ => None,
    }
}

const TYPES: u32 = (1 << 1) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 7) | (1 << 8);

impl Kind {
    fn pub_len(self) -> usize {
        match self {
            Kind::X25519 | Kind::Ed25519 => 32,
            Kind::P256 => 65,
            Kind::P384 => 97,
        }
    }

    fn signs(self) -> bool {
        self != Kind::X25519
    }

    fn derives(self) -> bool {
        self != Kind::Ed25519
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

// Sizes are baked into the ioctl numbers.
static_assert!(core::mem::size_of::<Info>() == 32);
static_assert!(core::mem::size_of::<Create>() == 1156);
static_assert!(core::mem::size_of::<Sign>() == 2192);
static_assert!(core::mem::size_of::<Ecdh>() == 1204);
static_assert!(core::mem::size_of::<Pubkey>() == 1156);
static_assert!(core::mem::size_of::<Auth>() == 32);
static_assert!(core::mem::size_of::<AuthPoll>() == 32);

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

/// A struct's byte image, read from and written back to userspace.
struct Image {
    bytes: KVec<u8>,
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

/// Whether the blob carries a `cbio` constraint (created gated): its `ed`
/// member holds the ACL the create answered.
fn is_gated(blob: &[u8]) -> bool {
    crate::der::refkey_find(blob, b"ed").is_some_and(|ed| ed.windows(6).any(|w| w == b"\x0c\x04cbio"))
}

/// The blob at `off`, its length in head word `len_word`.
fn blob_in(img: &Image, len_word: usize) -> Result<&[u8]> {
    let n = img.word(len_word) as usize;
    if n == 0 || n > BLOB_MAX {
        return Err(EINVAL);
    }
    Ok(img.field(HEAD, n))
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
    /// The last verify's end, for AUTH_POLL after it.
    last: u32,
    last_status: u32,
}

impl AuthState {
    fn credit_left_ns(&self) -> Option<u64> {
        let until = self.credit_until_ns?;
        let now = crate::shim::boottime_ns();
        (now < until).then(|| until - now)
    }
}

/// Per open file: the uid of its opener, whose bag every operation uses, and
/// its AUTH.
pub(crate) struct KeyFile {
    uid: u32,
    // Every callback for a file runs under the shim's device mutex
    // (key_shim.c), so one at a time: that is the only access.
    auth: core::cell::UnsafeCell<AuthState>,
}

impl KeyFile {
    fn new(uid: u32) -> KeyFile {
        KeyFile {
            uid,
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
        let loaded = self.user_bags.lock().loaded(file.uid);
        let mut flags = 0;
        if crate::userbag::stored(file.uid) {
            flags |= INFO_BAG_STORED;
        }
        if loaded {
            flags |= INFO_BAG_LOADED;
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
        if kind_of(kt).is_none() || flags & !CREATE_BIOMETRY != 0 {
            return Err(EINVAL);
        }
        let r = if flags & CREATE_BIOMETRY != 0 {
            // On the bag designated to the fingers' SEP user: an undesignated
            // user bag answers -9 to a gated key whatever the match (H2b P3.0).
            if !self.key_bio_ready(file) {
                return Err(errno::opnotsupp());
            }
            let ed = self.key_gated_ed()?;
            let der = crate::der::encode_refkey_set(&[
                (b"bc", RV::Integer(class)),
                (b"ed", RV::Der(&ed)),
                (b"kt", RV::Integer(kt)),
                (b"o", RV::Utf8(b"oc")),
            ])?;
            self.key_identity_op(&der)?
        } else {
            let der = crate::der::encode_refkey_set(&[
                (b"bc", RV::Integer(class)),
                (b"kt", RV::Integer(kt)),
                (b"o", RV::Utf8(b"oc")),
            ])?;
            self.user_bag_op(&mut self.user_bags.lock(), file.uid, true, &der)?
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
        let (_kt, kind, _) = parse_blob(blob)?;
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
            let r = self.key_identity_op(&der)?;
            self.key_credit_used(file, r.status);
            r
        } else {
            let der = crate::der::encode_refkey_set(&[
                (b"d", RV::Octets(data)),
                (b"o", RV::Utf8(b"osgn")),
                (b"rk", RV::Der(blob)),
            ])?;
            self.user_bag_op(&mut self.user_bags.lock(), file.uid, false, &der)?
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
        let (_kt, kind, _) = parse_blob(blob)?;
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
            let r = self.key_identity_op(&der)?;
            self.key_credit_used(file, r.status);
            r
        } else {
            let der = crate::der::encode_refkey_set(&[
                (b"o", RV::Utf8(b"ock")),
                (b"pub", RV::Octets(peer)),
                (b"rk", RV::Der(blob)),
            ])?;
            self.user_bag_op(&mut self.user_bags.lock(), file.uid, false, &der)?
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
        let gated = is_gated(blob);
        let mut copy = KVec::new();
        copy.extend_from_slice(public, GFP_KERNEL)?;
        img.put(HEAD + BLOB_MAX, PUB_MAX, &copy)?;
        img.set_word(1, kt);
        img.set_word(2, copy.len() as u32);
        img.set_word(3, if gated { PUBKEY_BIOMETRY } else { 0 });
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

    /// Gives the Touch ID session back after the file's verify ended or was
    /// cancelled.
    fn key_auth_release_session(&self, auth: &mut AuthState, cancel: bool) {
        {
            let mut session = self.bio_session.lock();
            if cancel {
                let _ = crate::bio::abort_capture(&mut session);
            }
            crate::bio::release(&mut session);
            *self.key_auth_acm.lock() = None;
        }
        auth.pending = false;
        if let Some(dev) = self.bio_dev.lock().as_ref() {
            dev.wake();
        }
    }

    /// Whether this uid can have gated keys now.
    fn key_bio_ready(&self, file: &KeyFile) -> bool {
        file.uid as i32 == BIO_USER && self.templates_restored.load(Relaxed)
    }

    /// SEP_KEY_AUTH: a fresh context and a verify that credits it. True when
    /// the caller must queue the verify work item.
    fn key_auth_start(&self, file: &KeyFile, img: &Image) -> Result<bool> {
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
        let acm = self.key_acm_create()?;
        let started = {
            let mut session = self.bio_session.lock();
            let index = self.bio_index.lock();
            let mut ctx = crate::bio::Context {
                session: &mut session,
                index: &index,
                sensor_present: crate::sensor::is_bound(),
                live_identity_count: None,
            };
            let r = crate::bio::key_auth_start(&mut ctx);
            if r.is_ok() {
                *self.key_auth_acm.lock() = Some(acm);
            }
            r
        };
        if let Err(e) = started {
            let _ = self.scrd_command(&crate::scrd::scrd_context_destroy(&acm));
            return Err(e);
        }
        *auth = AuthState {
            acm: Some(acm),
            pending: true,
            window,
            window_s,
            credit_until_ns: None,
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
            let state = crate::bio::key_auth_poll(&self.bio_session.lock());
            match state {
                crate::bio::KeyAuthState::Pending(g) => guidance = g as u32,
                crate::bio::KeyAuthState::Matched => {
                    self.key_auth_release_session(auth, false);
                    let s = if auth.window { auth.window_s } else { AUTH_HOLD_S };
                    auth.credit_until_ns = Some(crate::shim::boottime_ns() + u64::from(s) * 1_000_000_000);
                    auth.last = AUTH_MATCH;
                }
                crate::bio::KeyAuthState::NoMatch => {
                    self.key_auth_release_session(auth, false);
                    self.key_auth_forget(auth);
                    auth.last = AUTH_NOMATCH;
                }
                crate::bio::KeyAuthState::Failed(status) => {
                    self.key_auth_release_session(auth, false);
                    self.key_auth_forget(auth);
                    auth.last = AUTH_FAILED;
                    auth.last_status = status;
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
        if auth.pending {
            self.key_auth_release_session(auth, true);
        }
        self.key_auth_forget(auth);
        auth.last = AUTH_IDLE;
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
    fn key_identity_op(&self, der: &[u8]) -> Result<OpReply> {
        let _one = self.key_identity_lock.lock();
        let crate::keybag::State::Present(stored) = crate::keybag::read(crate::keybag::Slot::Identity)? else {
            return Err(ENODEV);
        };
        let (handle, _uuid) = self.sks_recover(&stored).ok_or(EIO)?;
        let result = (|| {
            let healthy = self.sks_health_check(c"sep-key gated").ok_or(EIO)?;
            let out = self
                .sks_send(self.sks_req_change_lock_state(
                    handle,
                    crate::LockState::Unlocked,
                    stored.secret(),
                    healthy,
                ))
                .ok_or(EIO)?;
            if out.reply.status != 0 {
                return Err(EIO);
            }
            let out = self.sks_send(self.sks_req_refkey(handle.value(), der)).ok_or(EIO)?;
            let mut body = KVec::new();
            if out.reply.status == 0 {
                let b = self
                    .sks_report_response(crate::sks::SKS_PERFORM_OP_NAME, &out)
                    .ok_or(EIO)?;
                body.extend_from_slice(b, GFP_KERNEL)?;
            }
            Ok(OpReply { status: out.reply.status, body })
        })();
        let _ = self.sks_send(self.sks_req_unload_keybag(handle));
        result
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
