// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Rust side of `touch_shim.c`: the `touch` attribute, whether the Touch ID
//! sensor waits for a finger and for whom.

use core::fmt::Write;

use kernel::{device, prelude::*};

use crate::bio::{Guidance, TouchState};

extern "C" {
    // `struct device *`, untyped as in diag.rs.
    fn sep_touch_register(dev: *mut c_void) -> c_int;
    fn sep_touch_unregister();
    fn sep_touch_set(line: *const u8, len: usize);
    fn sep_current_comm(buf: *mut u8, cap: usize) -> usize;
}

/// The calling task's name.
pub(crate) fn current_comm() -> [u8; 16] {
    let mut buf = [0u8; 16];
    // SAFETY: `buf` is valid for its length; the shim NUL-terminates within it.
    unsafe { sep_current_comm(buf.as_mut_ptr(), buf.len()) };
    buf
}

pub(crate) fn register(dev: &device::Device<device::Bound>) -> Result {
    // SAFETY: a bound device; devres removes the group at unbind.
    let ret = unsafe { sep_touch_register(dev.as_raw().cast()) };
    if ret == 0 { Ok(()) } else { Err(Error::from_errno(ret)) }
}

pub(crate) fn unregister() {
    // SAFETY: no arguments; later stores only update the line.
    unsafe { sep_touch_unregister() };
}

struct Line {
    buf: [u8; 128],
    n: usize,
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let b = s.as_bytes();
        let k = b.len().min(self.buf.len() - self.n);
        self.buf[self.n..self.n + k].copy_from_slice(&b[..k]);
        self.n += k;
        Ok(())
    }
}

fn guidance(g: Guidance) -> &'static str {
    match g {
        Guidance::None => "none",
        Guidance::Place => "place",
        Guidance::LiftAndMove => "lift-and-move",
        Guidance::HoldStill => "hold-still",
    }
}

/// Publishes the session's state (wakes pollers when the line changes).
pub(crate) fn publish(state: TouchState) {
    let mut l = Line { buf: [0u8; 128], n: 0 };
    let _ = match state {
        TouchState::Idle => write!(l, "idle"),
        TouchState::Verify { guide, key: Some((uid, comm)) } => {
            let n = comm.iter().position(|&c| c == 0).unwrap_or(comm.len());
            let comm = core::str::from_utf8(&comm[..n]).unwrap_or("?");
            write!(l, "verify sep-key uid={} comm={} guidance={}", uid, comm, guidance(guide))
        }
        TouchState::Verify { guide, key: None } => write!(l, "verify sep-bio guidance={}", guidance(guide)),
        TouchState::Enrol { guide } => write!(l, "enrol sep-bio guidance={}", guidance(guide)),
    };
    // SAFETY: `l.buf` holds `l.n` valid bytes.
    unsafe { sep_touch_set(l.buf.as_ptr(), l.n) };
}
