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

use kernel::ioctl::{_IOR, _IOWR};
use kernel::prelude::*;
use kernel::uaccess::{UserPtr, UserSlice};

use crate::der::RefKeyValue as RV;
use crate::userbag::OpReply;
use crate::SepData;

pub(crate) const IFACE_VERSION: u32 = 1;

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

/// The enclave's status for an operation the key's type does not have.
const STATUS_NOT_FOR_TYPE: i8 = -12;
/// For a ref key wrapped under another bag (K0).
const STATUS_OTHER_BAG: i8 = -7;
/// For a set it cannot parse (H2: the inner rk set instead of the whole one).
const STATUS_BAD_SET: i8 = -10;

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

const HEAD: usize = 32;

const MAGIC: u32 = 0xB2;

const IOC_GET_INFO: u32 = _IOR::<Info>(MAGIC, 0x01);
const IOC_CREATE: u32 = _IOWR::<Create>(MAGIC, 0x02);
const IOC_SIGN: u32 = _IOWR::<Sign>(MAGIC, 0x03);
const IOC_ECDH: u32 = _IOWR::<Ecdh>(MAGIC, 0x04);
const IOC_PUBKEY: u32 = _IOWR::<Pubkey>(MAGIC, 0x05);

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

/// Per open file: the uid of its opener, whose bag every operation uses.
pub(crate) struct KeyFile {
    uid: u32,
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
        if kind_of(kt).is_none() || img.word(2) != 0 {
            return Err(EINVAL);
        }
        let der = crate::der::encode_refkey_set(&[
            (b"bc", RV::Integer(class)),
            (b"kt", RV::Integer(kt)),
            (b"o", RV::Utf8(b"oc")),
        ])?;
        let r = self.user_bag_op(&mut self.user_bags.lock(), file.uid, true, &der)?;
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
        let der = crate::der::encode_refkey_set(&[
            (b"d", RV::Octets(data)),
            (b"o", RV::Utf8(b"osgn")),
            (b"rk", RV::Der(blob)),
        ])?;
        let r = self.user_bag_op(&mut self.user_bags.lock(), file.uid, false, &der)?;
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
        let der = crate::der::encode_refkey_set(&[
            (b"o", RV::Utf8(b"ock")),
            (b"pub", RV::Octets(peer)),
            (b"rk", RV::Der(blob)),
        ])?;
        let r = self.user_bag_op(&mut self.user_bags.lock(), file.uid, false, &der)?;
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
        let mut copy = KVec::new();
        copy.extend_from_slice(public, GFP_KERNEL)?;
        img.put(HEAD + BLOB_MAX, PUB_MAX, &copy)?;
        img.set_word(1, kt);
        img.set_word(2, copy.len() as u32);
        Ok(())
    }

    fn key_ioctl(&self, file: &KeyFile, cmd: u32, arg: usize) -> Result<()> {
        let user = UserPtr::from_addr(arg);
        let (len, run): (usize, fn(&SepData, &KeyFile, &mut Image) -> Result<()>) = match cmd {
            IOC_GET_INFO => return self.key_get_info(file, user),
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
        done
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
    let opened = KBox::new(KeyFile { uid }, GFP_KERNEL)
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
    this.user_bag_close(&mut this.user_bags.lock(), file.uid);
}

/// # Safety
unsafe extern "C" fn key_ioctl(ctx: *mut c_void, fctx: *mut c_void, cmd: c_uint, arg: c_ulong) -> c_long {
    // SAFETY: per the contract above.
    let (this, file) = unsafe { (&*ctx.cast::<SepData>(), &*fctx.cast::<KeyFile>()) };
    match this.key_ioctl(file, cmd, arg as usize) {
        Ok(()) => 0,
        Err(e) => e.to_errno() as c_long,
    }
}
