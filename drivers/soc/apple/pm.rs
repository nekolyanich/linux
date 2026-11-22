// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! System sleep. A Touch ID capture runs on a non-freezable workqueue and keeps
//! talking to the sensor over SPI, so one left running into a suspend is still
//! active while devices go down. A J313 that suspended with the lock screen's
//! capture in flight did not wake. Before the system suspends, end any capture
//! in progress and hold new ones until it has resumed. The hwrng fill thread
//! is not frozen either, so entropy requests are held over the same window,
//! and once the driver's own sleep traffic is done every other send is
//! refused until the resume. The notifier itself is in `pm_shim.c`; the capture and entropy handling is
//! on [`SepData`].

use core::sync::atomic::{AtomicPtr, Ordering};

use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::types::ForeignOwnable;

use crate::SepData;

/// The notifier has no context pointer, so `SepData` is reached through this
/// global, as in `trusted.rs`. Holds the [`ForeignOwnable::into_foreign`]
/// pointer while registered; `null` otherwise.
static SEP: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

extern "C" {
    fn sep_pm_register(event: unsafe extern "C" fn(bool) -> c_int) -> c_int;
    fn sep_pm_unregister();
    fn sep_pm_keep_domains(dev: *mut c_void) -> c_int;
    fn sep_pm_register_sleep(
        dev: *mut c_void,
        sleep: unsafe extern "C" fn() -> c_int,
        wake: unsafe extern "C" fn(bool),
        told: unsafe extern "C" fn() -> bool,
    ) -> c_int;
    fn sep_pm_unregister_sleep(dev: *mut c_void);
    fn sep_pm_clear_dev_disable(dev: *mut c_void) -> c_int;
    fn sep_pm_dart_restore(dev: *mut c_void);
    fn sep_pm_dart_hold(dev: *mut c_void, hold: bool) -> c_int;
    fn sep_pm_crumb(stage: u8);
    fn sep_pm_gated(dev: *mut c_void) -> bool;
    fn sep_pm_set_gate(gate: u32);
    pub(crate) static sep_pm_ops: kernel::bindings::dev_pm_ops;
}

/// Who may use the mailbox around the bench's early SLEEP (native5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SleepGate {
    /// Anyone.
    Open = 0,
    /// Replies to what the enclave asked, and the sleep request itself.
    Draining = 1,
    /// Nobody until the wake: the enclave is gated or about to be.
    Told = 2,
    /// Nobody: a SLEEP or its wake failed. Stays so until a reboot.
    Lost = 3,
}

impl SleepGate {
    pub(crate) fn from_u32(v: u32) -> SleepGate {
        match v {
            0 => SleepGate::Open,
            1 => SleepGate::Draining,
            2 => SleepGate::Told,
            _ => SleepGate::Lost,
        }
    }
}

/// Puts the enclave's DART back if it lost its state, before the doorbell.
pub(crate) fn dart_restore(dev: &kernel::device::Device) {
    // SAFETY: `dev` is the bound SEP device.
    unsafe { sep_pm_dart_restore(dev.as_raw().cast()) };
}

/// The early SLEEP's DART: saved and left alone before the send (`hold`), or given back
/// unchanged when the request did not go out. [`dart_restore`] undoes a hold at the wake.
pub(crate) fn dart_hold(dev: &kernel::device::Device, hold: bool) -> Result<()> {
    // SAFETY: `dev` is the bound SEP device.
    let rc = unsafe { sep_pm_dart_hold(dev.as_raw().cast(), hold) };
    if rc != 0 {
        return Err(Error::from_errno(rc));
    }
    Ok(())
}

/// A bench crumb (PMU boot_stage); a no-op off the native bench.
pub(crate) fn crumb(stage: u8) {
    // SAFETY: no preconditions.
    unsafe { sep_pm_crumb(stage) };
}

/// Whether the enclave has gated its own power domain, now.
pub(crate) fn gated(dev: &kernel::device::Device) -> bool {
    // SAFETY: `dev` is the bound SEP device.
    unsafe { sep_pm_gated(dev.as_raw().cast()) }
}

/// The enclave refused the last SLEEP (4 in sysfs and the bench's entry crumb).
pub(crate) fn publish_refused() {
    // SAFETY: no preconditions.
    unsafe { sep_pm_set_gate(4) };
}

/// The gate as sysfs shows it (`sleep_gate`).
pub(crate) fn publish_gate(gate: SleepGate) {
    // SAFETY: no preconditions.
    unsafe { sep_pm_set_gate(gate as u32) };
}

/// Lets a gated enclave start again. Writes only if the bit is set.
pub(crate) fn clear_dev_disable(dev: &kernel::device::Device) -> Result<()> {
    // SAFETY: `dev` is the bound SEP device.
    let rc = unsafe { sep_pm_clear_dev_disable(dev.as_raw().cast()) };
    if rc != 0 {
        return Err(Error::from_errno(rc));
    }
    Ok(())
}

/// Runs `f` on the registered instance. Only for callbacks that the bound device excludes.
fn with_sep<R>(none: R, f: impl FnOnce(&SepData) -> R) -> R {
    let ptr = SEP.load(Ordering::Acquire);
    if ptr.is_null() {
        return none;
    }
    // SAFETY: as in `pm_event`: the device callbacks run only while bound, and
    // `unregister` clears them before reclaiming the `Arc`.
    let sep = unsafe { <Arc<SepData> as ForeignOwnable>::borrow(ptr) };
    f(&*sep)
}

/// # Safety
/// Called by `pm_shim.c` from the device's suspend callback, with the early SLEEP on.
unsafe extern "C" fn pm_sleep() -> c_int {
    with_sep(0, |sep| match sep.sleep_enter_early() {
        Ok(()) => 0,
        Err(e) => e.to_errno(),
    })
}

/// # Safety
/// Called by `pm_shim.c` from the device's resume callback.
unsafe extern "C" fn pm_wake(real: bool) {
    with_sep((), |sep| sep.sleep_exit(real));
}

/// # Safety
/// Called by `pm_shim.c`, whether or not the device suspended.
unsafe extern "C" fn pm_told() -> bool {
    with_sep(false, |sep| sep.sleep_gate() == SleepGate::Told)
}

/// Attaches every power domain of a multi-domain SEP node and keeps them on
/// across system sleep; see `pm_shim.c`. Must run before the enclave is first
/// spoken to.
pub(crate) fn keep_domains(dev: &kernel::device::Device) -> Result<()> {
    // SAFETY: `dev` is the bound SEP device; the shim ties what it attaches to
    // that device's lifetime through devres.
    let rc = unsafe { sep_pm_keep_domains(dev.as_raw().cast()) };
    if rc != 0 {
        return Err(Error::from_errno(rc));
    }
    Ok(())
}

/// The holds a sleep event takes and releases, on [`SepData`].
trait SleepHolds {
    /// Holds entropy requests, once any in flight is answered.
    fn hold_entropy(&self);
    /// Ends any Touch ID capture and holds new ones.
    fn hold_captures(&self) -> Result<()>;
    fn release_captures(&self);
    fn release_entropy(&self);
    /// Refuses every send to the enclave until [`Self::release_sends`].
    fn hold_sends(&self);
    fn release_sends(&self);
}

impl SleepHolds for SepData {
    fn hold_entropy(&self) {
        self.rng_sleep_prepare();
    }
    fn hold_captures(&self) -> Result<()> {
        self.sleep_prepare()
    }
    fn release_captures(&self) {
        self.sleep_finished();
    }
    fn release_entropy(&self) {
        self.rng_sleep_finished();
    }
    fn hold_sends(&self) {
        self.sleep_hold_sends();
    }
    fn release_sends(&self) {
        self.sleep_release_sends();
    }
}

/// `entering`: the system is about to sleep; otherwise it has resumed, or
/// the suspend was aborted.
fn sleep_event(sep: &impl SleepHolds, entering: bool) -> Result<()> {
    if entering {
        sep.hold_entropy();
        if let Err(error) = sep.hold_captures() {
            // A failing notifier is not included in the PM chain's rollback.
            sep.release_captures();
            sep.release_entropy();
            return Err(error);
        }
        // Holding captures was the last thing to talk to the enclave. A
        // message it is sent while devices are suspended is never answered,
        // and from then on it reads no more of its mailbox.
        sep.hold_sends();
    } else {
        sep.release_sends();
        sep.release_captures();
        sep.release_entropy();
    }
    Ok(())
}

/// # Safety
/// Called by `pm_shim.c` from the PM notifier chain, in process context.
unsafe extern "C" fn pm_event(entering: bool) -> c_int {
    let ptr = SEP.load(Ordering::Acquire);
    if ptr.is_null() {
        return 0;
    }
    // SAFETY: produced by `into_foreign` in `register`, and reclaimed by
    // `unregister` only after `sep_pm_unregister` has waited out any running
    // notifier call, so it is live for this borrow.
    let sep = unsafe { <Arc<SepData> as ForeignOwnable>::borrow(ptr) };
    match sleep_event(&*sep, entering) {
        Ok(()) => 0,
        Err(error) => error.to_errno(),
    }
}

pub(crate) fn register(sep: Arc<SepData>) -> Result<()> {
    let dev: *mut c_void = sep.dev.as_raw().cast();
    let ptr = sep.into_foreign();

    if SEP
        .compare_exchange(
            core::ptr::null_mut(),
            ptr,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        // SAFETY: `ptr` was just produced by `into_foreign` and never published.
        drop(unsafe { <Arc<SepData> as ForeignOwnable>::from_foreign(ptr) });
        return Err(EBUSY);
    }

    // SAFETY: the shim stores the callback and registers a notifier block
    // that lives for the module's lifetime.
    let rc = unsafe { sep_pm_register(pm_event) };
    if rc != 0 {
        let raw = SEP.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !raw.is_null() {
            // SAFETY: `raw` is the pointer we published; no notifier is wired.
            drop(unsafe { <Arc<SepData> as ForeignOwnable>::from_foreign(raw) });
        }
        return Err(Error::from_errno(rc));
    }
    // SAFETY: `dev` is the bound SEP device, unregistered in `unregister` before the
    // `Arc` is reclaimed.
    if unsafe { sep_pm_register_sleep(dev, pm_sleep, pm_wake, pm_told) } != 0 {
        pr_warn!("sep: the sleep_gate attribute wasn't created\n");
    }
    Ok(())
}

/// Safe to call even if [`register`] never ran. Unregisters the notifier,
/// which waits for a running call to finish, before reclaiming the `Arc`.
pub(crate) fn unregister() {
    if SEP.load(Ordering::Acquire).is_null() {
        return;
    }
    // SAFETY: no preconditions; matched with `sep_pm_register` above.
    unsafe { sep_pm_unregister() };

    let ptr = SEP.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !ptr.is_null() {
        // SAFETY: `ptr` is live until reclaimed below; only its device pointer is read.
        let sep = unsafe { <Arc<SepData> as ForeignOwnable>::borrow(ptr) };
        // SAFETY: matched with `sep_pm_register_sleep` in `register`.
        unsafe { sep_pm_unregister_sleep(sep.dev.as_raw().cast()) };
    }
    if !ptr.is_null() {
        // SAFETY: `ptr` came from `into_foreign` in `register`, and the
        // notifier can no longer call `pm_event`.
        drop(unsafe { <Arc<SepData> as ForeignOwnable>::from_foreign(ptr) });
    }
}

#[kernel::macros::kunit_tests(apple_sep_pm)]
mod tests {
    use super::*;
    use core::cell::{Cell, RefCell};

    const HOLD_ENTROPY: u8 = 1;
    const HOLD_CAPTURES: u8 = 2;
    const RELEASE_CAPTURES: u8 = 3;
    const RELEASE_ENTROPY: u8 = 4;
    const HOLD_SENDS: u8 = 5;
    const RELEASE_SENDS: u8 = 6;

    struct Calls {
        made: RefCell<[u8; 8]>,
        count: Cell<usize>,
        refuse: Option<Error>,
    }

    impl Calls {
        fn new(refuse: Option<Error>) -> Self {
            Calls {
                made: RefCell::new([0; 8]),
                count: Cell::new(0),
                refuse,
            }
        }
        fn call(&self, which: u8) {
            let n = self.count.get();
            self.made.borrow_mut()[n] = which;
            self.count.set(n + 1);
        }
        fn made(&self) -> [u8; 8] {
            *self.made.borrow()
        }
    }

    impl SleepHolds for Calls {
        fn hold_entropy(&self) {
            self.call(HOLD_ENTROPY);
        }
        fn hold_captures(&self) -> Result<()> {
            self.call(HOLD_CAPTURES);
            self.refuse.map_or(Ok(()), Err)
        }
        fn release_captures(&self) {
            self.call(RELEASE_CAPTURES);
        }
        fn release_entropy(&self) {
            self.call(RELEASE_ENTROPY);
        }
        fn hold_sends(&self) {
            self.call(HOLD_SENDS);
        }
        fn release_sends(&self) {
            self.call(RELEASE_SENDS);
        }
    }

    #[test]
    fn going_to_sleep_holds_entropy_then_captures_then_sends() {
        let calls = Calls::new(None);
        assert_eq!(sleep_event(&calls, true), Ok(()));
        assert_eq!(
            calls.made(),
            [HOLD_ENTROPY, HOLD_CAPTURES, HOLD_SENDS, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn a_refused_sleep_releases_what_it_held() {
        // The chain sends no POST event to the notifier that failed.
        let calls = Calls::new(Some(EBUSY));
        assert_eq!(sleep_event(&calls, true), Err(EBUSY));
        assert_eq!(
            calls.made(),
            [
                HOLD_ENTROPY,
                HOLD_CAPTURES,
                RELEASE_CAPTURES,
                RELEASE_ENTROPY,
                0,
                0,
                0,
                0
            ]
        );
    }

    #[test]
    fn waking_releases_sends_then_captures_then_entropy() {
        let calls = Calls::new(None);
        assert_eq!(sleep_event(&calls, false), Ok(()));
        assert_eq!(
            calls.made(),
            [RELEASE_SENDS, RELEASE_CAPTURES, RELEASE_ENTROPY, 0, 0, 0, 0, 0]
        );
    }
}
