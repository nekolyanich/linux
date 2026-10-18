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
    fn sep_current_tgid() -> c_int;
}

/// The task behind a /dev/sep-key AUTH, as the `touch` line names it.
#[derive(Clone, Copy)]
pub(crate) struct Caller {
    /// Its process (thread group) id in the initial pid namespace.
    pid: i32,
    /// Its name, NUL-terminated: chosen by the task itself, so never trusted.
    comm: [u8; 16],
}

/// The calling task.
pub(crate) fn current_caller() -> Caller {
    let mut comm = [0u8; 16];
    // SAFETY: `comm` is valid for its length; the shim NUL-terminates within it.
    unsafe { sep_current_comm(comm.as_mut_ptr(), comm.len()) };
    // SAFETY: no preconditions; reads the current task.
    let pid = unsafe { sep_current_tgid() };
    Caller { pid, comm }
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

/// `SEP_TOUCH_MAX` in touch_shim.c: room for the longest line, a fully
/// escaped comm included.
const LINE_MAX: usize = 192;

struct Line {
    buf: [u8; LINE_MAX],
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

/// Writes a caller-chosen name so that it never holds a space, `=`, `\` or a
/// non-printable byte (those become `\xNN`): a name cannot forge another
/// field, and the line still ends in ` guidance=<g>`.
fn put_escaped(l: &mut Line, s: &[u8]) -> core::fmt::Result {
    for &c in s {
        if c.is_ascii_graphic() && c != b'=' && c != b'\\' {
            l.write_char(char::from(c))?;
        } else {
            write!(l, "\\x{:02x}", c)?;
        }
    }
    Ok(())
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
    let mut l = Line {
        buf: [0u8; LINE_MAX],
        n: 0,
    };
    let _ = match state {
        TouchState::Idle => write!(l, "idle"),
        TouchState::Verify { guide, key: Some((uid, who)) } => {
            let n = who.comm.iter().position(|&c| c == 0).unwrap_or(who.comm.len());
            write!(l, "verify sep-key uid={} pid={} comm=", uid, who.pid)
                .and_then(|()| put_escaped(&mut l, &who.comm[..n]))
                .and_then(|()| write!(l, " guidance={}", guidance(guide)))
        }
        TouchState::Verify { guide, key: None } => write!(l, "verify sep-bio guidance={}", guidance(guide)),
        TouchState::Enrol { guide } => write!(l, "enrol sep-bio guidance={}", guidance(guide)),
    };
    // SAFETY: `l.buf` holds `l.n` valid bytes.
    unsafe { sep_touch_set(l.buf.as_ptr(), l.n) };
}
