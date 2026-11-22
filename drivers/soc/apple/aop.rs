// SPDX-License-Identifier: GPL-2.0-only OR MIT
#![recursion_limit = "2048"]

//! Apple AOP driver
//!
//! Copyright (C) The Asahi Linux Contributors

use core::{
    arch::asm,
    cmp,
    marker::Unpin,
    mem,
    ptr,
    slice, //
};

use kernel::{
    bindings,
    c_str,
    device,
    device::Core,
    dma::{
        Coherent,
        Device,
        DmaMask, //
    },
    error::{
        from_err_ptr,
        to_result, //
    },
    io::{
        io_project,
        Io,
        IoBase,
        IoSysMap,
        Mmio,
        Region, //
    },
    module_platform_driver,
    new_condvar,
    new_mutex,
    of,
    platform,
    prelude::*,
    soc::apple::aop::{
        from_fourcc,
        EPICService,
        FakehidListener,
        AOP, //
    },
    soc::apple::rtkit::{
        self,
        ASC_CPU_CONTROL, //
    },
    sync::{
        aref::ARef,
        Arc,
        ArcBorrow,
        atomic::{
            Acquire,
            Atomic,
            Relaxed,
            Release, //
        },
        CondVar,
        CondVarTimeoutResult,
        Mutex, //
    },
    time::{
        msecs_to_jiffies,
        Jiffies, //
    },
    types::ForeignOwnable,
    workqueue::{
        self,
        impl_has_work,
        new_work,
        Work,
        WorkItem, //
    }, //
};

const AOP_MAX_CALLS: usize = 8;
const AOP_MMIO_SIZE: usize = 0x1e0000;
const ASC_MMIO_SIZE: usize = 0x4000;
const BOOTARGS_OFFSET: usize = 0x22c;
const BOOTARGS_SIZE: usize = 0x230;
const AFK_ENDPOINT_START: u8 = 0x20;
const AFK_ENDPOINT_COUNT: u8 = 0xf;
const AFK_OPC_GET_BUF: u64 = 0x89;
const AFK_OPC_INIT: u64 = 0x80;
const AFK_OPC_INIT_RX: u64 = 0x8b;
const AFK_OPC_INIT_TX: u64 = 0x8a;
const AFK_OPC_INIT_UNK: u64 = 0x8c;
const AFK_OPC_SEND: u64 = 0xa2;
const AFK_OPC_START_ACK: u64 = 0x86;
const AFK_OPC_SHUTDOWN_ACK: u64 = 0xc1;
const AFK_OPC_SLEEP_ACK: u64 = 0x87;
const AFK_OPC_RECV: u64 = 0x85;
const AFK_MSG_GET_BUF_ACK: u64 = 0xa1 << 48;
const AFK_MSG_INIT: u64 = AFK_OPC_INIT << 48;
const AFK_MSG_INIT_ACK: u64 = 0xa0 << 48;
const AFK_MSG_START: u64 = 0xa3 << 48;
const AFK_MSG_SHUTDOWN: u64 = 0xc0 << 48;
const AFK_MSG_SLEEP: u64 = 0xa4 << 48;
const AFK_RB_BLOCK_STEP: usize = 0x40;
const EPIC_TYPE_NOTIFY: u32 = 0;
const EPIC_CATEGORY_REPORT: u8 = 0x00;
const EPIC_CATEGORY_NOTIFY: u8 = 0x10;
const EPIC_CATEGORY_REPLY: u8 = 0x20;
const EPIC_SUBTYPE_STD_SERVICE: u16 = 0xc0;
const EPIC_SUBTYPE_FAKEHID_REPORT: u16 = 0xc4;
const EPIC_SUBTYPE_RETCODE: u16 = 0x84;
const EPIC_SUBTYPE_RETCODE_PAYLOAD: u16 = 0xa0;
const EPIC_SUBTYPE_STRING: u16 = 0x8a;
const QE_MAGIC1: u32 = from_fourcc(b" POI");
const QE_MAGIC2: u32 = from_fourcc(b" POA");

// System sleep (aurora's AOP sleep, by function, and native5's t6020 bench pieces; Tanabota
// m2pro-73-port.md, batch 9). Off unless a sleep reaches the firmware or apple_sleep.aop_sleep.
/// macOS 13's t6020 order of its AFK SLEEPs (Tanabota pd632): 0x26 first, 0x23 and 0x24 not at
/// all. Only the bench's AOPORDER group (apple_sleep.groups bit 62) uses it.
const AOP_SLEEP_ORDER_MACOS_T6020: &[u8] = &[0x26, 0x21, 0x20, 0x22, 0x2b, 0x25, 0x2c, 0x29, 0x2a, 0x28, 0x2d, 0x27];
/// The EPIC notices macOS 13 puts on these t6020 endpoints between its first AFK SLEEP (0x26) and
/// the others (pd632, 1 of 1): ring magic "AOP ", the channel here, type 0 (notify), EPIC v2
/// header with category 0x10 and subtype 4, and 12 bytes of zeros. Only the bench's AOPSEND
/// group (bit 63) sends them.
const AOP_SLEEP_NOTICES_MACOS_T6020: &[(u8, u32)] = &[
    (0x21, 0x1000_0007),
    (0x22, 0x1000_0008),
    (0x25, 0),
    (0x29, 0x1000_0010),
    (0x2a, 0x1000_0005),
    (0x2b, 0x1000_000d),
    (0x2c, 0x1000_000c),
    (0x2d, 0x1000_0009),
];
const AOP_SLEEP_NOTICE_SUBTYPE: u16 = 4;
/// The channel the t6020 firmware announces "wakehint" on (pd633).
const AOP_WAKEHINT_CHANNEL_T6020: u32 = 0x1000_0001;
const AOP_SLEEP_NOTICE_LEN: usize = 12;
/// Bound on the answer to each stop or start around a system sleep.
const AFK_SLEEP_TIMEOUT_MS: u32 = 1000;
/// Bound on an EPIC call's reply (aurora's): a lost reply fails the call instead of wedging
/// its task, which would then refuse every later system sleep's freeze.
const EPIC_CALL_TIMEOUT_MS: u32 = 5000;

/// Index into the AFK endpoint tables for RTKit endpoint `ep`, if it is one of this driver's.
fn afk_endpoint_index(ep: u8) -> Option<usize> {
    ep.checked_sub(AFK_ENDPOINT_START)
        .map(usize::from)
        .filter(|&i| i < AFK_ENDPOINT_COUNT as usize)
}

fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

#[inline(always)]
fn mem_sync() {
    unsafe {
        asm!("dsb sy");
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct QEHeader {
    magic: u32,
    size: u32,
    channel: u32,
    ty: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct EPICHeader {
    version: u8,
    seq: u16,
    _pad0: u8,
    _unk0: u32,
    timestamp: u64,
    // Subheader
    length: u32,
    sub_version: u8,
    category: u8,
    subtype: u16,
    tag: u16,
    _unk1: u16,
    _pad1: u64,
    inline_len: u32,
}

#[repr(C, packed)]
struct EPICServiceAnnounce {
    name: [u8; 20],
    _unk0: u32,
    retcode: u32,
    _unk1: u32,
    channel: u32,
    _unk2: u32,
    _unk3: u32,
}

#[pin_data]
struct FutureValue<T> {
    #[pin]
    val: Mutex<Option<T>>,
    #[pin]
    completion: CondVar,
}

impl<T: Unpin> FutureValue<T> {
    fn pin_init() -> impl PinInit<FutureValue<T>> {
        pin_init!(
            FutureValue {
                val <- new_mutex!(None),
                completion <- new_condvar!()
            }
        )
    }
    fn complete(&self, val: T) {
        *self.val.lock() = Some(val);
        self.completion.notify_all();
    }
    fn wait(&self) -> T {
        let mut ret_guard = self.val.lock();
        while ret_guard.is_none() {
            self.completion.wait(&mut ret_guard);
        }
        ret_guard.take().unwrap()
    }
    /// Waits at most `timeout_ms` for the value, uninterruptibly: `None` if it did not arrive.
    fn wait_timeout(&self, timeout_ms: u32) -> Option<T> {
        let mut left: Jiffies = msecs_to_jiffies(timeout_ms);
        let mut ret_guard = self.val.lock();
        while ret_guard.is_none() {
            match self.completion.wait_timeout(&mut ret_guard, left) {
                CondVarTimeoutResult::Timeout => break,
                CondVarTimeoutResult::Woken { jiffies }
                | CondVarTimeoutResult::Signal { jiffies } => left = jiffies,
            }
        }
        ret_guard.take()
    }
    fn reset(&self) {
        *self.val.lock() = None;
    }
}

struct AFKRingBuffer {
    offset: usize,
    block_size: usize,
    buf_size: usize,
}

struct CallResult {
    retcode: u32,
    extra_data: Option<KVec<u8>>,
}

struct AFKEndpoint {
    index: u8,
    iomem: Option<Coherent<[u8]>>,
    txbuf: Option<AFKRingBuffer>,
    rxbuf: Option<AFKRingBuffer>,
    seq: u16,
    calls: [Option<Arc<FutureValue<CallResult>>>; AOP_MAX_CALLS],
    call_returns: [Option<KVec<u8>>; AOP_MAX_CALLS],
    /// A call whose caller gave up waiting (aurora's abandon_call): its tag stays reserved, so
    /// a later call doesn't get it and its late reply, until that reply arrives.
    abandoned: [bool; AOP_MAX_CALLS],
    /// The next send uses the ring magic "AOP " (macOS's sleep notices) instead of "IOP ".
    tx_magic_aop: bool,
}

unsafe impl Send for AFKEndpoint {}

impl AFKEndpoint {
    fn new(index: u8) -> AFKEndpoint {
        AFKEndpoint {
            index,
            iomem: None,
            txbuf: None,
            rxbuf: None,
            seq: 0,
            calls: [const { None }; AOP_MAX_CALLS],
            call_returns: [const { None }; AOP_MAX_CALLS],
            abandoned: [false; AOP_MAX_CALLS],
            tx_magic_aop: false,
        }
    }

    fn start(&self, rtkit: Pin<&mut rtkit::RtKit<AopData>>) -> Result<()> {
        rtkit.send_message(self.index, AFK_MSG_INIT)
    }

    fn stop(&self, rtkit: Pin<&mut rtkit::RtKit<AopData>>) -> Result<()> {
        rtkit.send_message(self.index, AFK_MSG_SHUTDOWN)
    }

    fn recv_message(
        &mut self,
        client: ArcBorrow<'_, AopData>,
        rtkit: Pin<&mut rtkit::RtKit<AopData>>,
        msg: u64,
    ) -> Result<()> {
        let opc = msg >> 48;
        match opc {
            AFK_OPC_INIT => {
                rtkit.send_message(self.index, AFK_MSG_INIT_ACK)?;
            }
            AFK_OPC_GET_BUF => {
                self.recv_get_buf(client.dev.clone(), rtkit, msg)?;
            }
            AFK_OPC_INIT_UNK => {} // no-op
            // Only a sleep waits for these; anything else leaves the value unread.
            AFK_OPC_START_ACK | AFK_OPC_SLEEP_ACK => client.sleep_answered(self.index),
            AFK_OPC_INIT_RX => {
                if self.rxbuf.is_some() {
                    dev_err!(
                        client.dev,
                        "Got InitRX message with existing rxbuf at endpoint {}",
                        self.index
                    );
                    return Err(EIO);
                }
                self.rxbuf = Some(self.parse_ring_buf(msg)?);
                if self.txbuf.is_some() {
                    rtkit.send_message(self.index, AFK_MSG_START)?;
                }
            }
            AFK_OPC_INIT_TX => {
                if self.txbuf.is_some() {
                    dev_err!(
                        client.dev,
                        "Got InitTX message with existing txbuf at endpoint {}",
                        self.index
                    );
                    return Err(EIO);
                }
                self.txbuf = Some(self.parse_ring_buf(msg)?);
                if self.rxbuf.is_some() {
                    rtkit.send_message(self.index, AFK_MSG_START)?;
                }
            }
            AFK_OPC_RECV => {
                self.recv_rb(client)?;
            }
            AFK_OPC_SHUTDOWN_ACK => {
                client.shutdown_complete();
            }
            _ => dev_err!(
                client.dev,
                "AFK endpoint {} got unknown message {}",
                self.index,
                msg
            ),
        }
        Ok(())
    }

    fn parse_ring_buf(&self, msg: u64) -> Result<AFKRingBuffer> {
        let msg = msg as usize;
        let size = ((msg >> 16) & 0xFFFF) * AFK_RB_BLOCK_STEP;
        let offset = ((msg >> 32) & 0xFFFF) * AFK_RB_BLOCK_STEP;
        let buf_size = self.iomem_read32(offset)? as usize;
        let block_size = (size - buf_size) / 3;
        Ok(AFKRingBuffer {
            offset,
            block_size,
            buf_size,
        })
    }
    fn iomem_write32(&mut self, off: usize, data: u32) -> Result<()> {
        let size = core::mem::size_of::<u32>();
        let data = data.to_le_bytes();
        let iomem = &self.iomem.as_mut().ok_or(ENXIO)?;
        let buf = unsafe { &mut iomem.as_mut()[off..off + size] };
        buf.copy_from_slice(&data);
        Ok(())
    }

    fn iomem_read32(&self, off: usize) -> Result<u32> {
        let size = core::mem::size_of::<u32>();
        let iomem = &self.iomem.as_ref().ok_or(ENXIO)?;
        let buf = unsafe { &iomem.as_ref()[off..off + size] };
        Ok(u32::from_le_bytes(buf.try_into().unwrap()))
    }

    fn memcpy_from_iomem(&self, off: usize, target: &mut [u8]) -> Result<()> {
        let iomem = &self.iomem.as_ref().ok_or(ENXIO)?;
        // SAFETY:
        // as_slice() checks that off and target.len() are whithin iomem's limits.
        unsafe {
            let src = &iomem.as_ref()[off..off + target.len()];
            target.copy_from_slice(src);
        }
        Ok(())
    }

    fn memcpy_to_iomem(&mut self, off: usize, src: &[u8]) -> Result<()> {
        let iomem = &self.iomem.as_mut().ok_or(ENXIO)?;
        // SAFETY:
        // as_slice_mut() checks that off and src.len() are whithin iomem's limits.
        unsafe {
            let target = &mut iomem.as_mut()[off..off + src.len()];
            target.copy_from_slice(src);
        }
        Ok(())
    }

    fn recv_get_buf(
        &mut self,
        dev: ARef<device::Device>,
        rtkit: Pin<&mut rtkit::RtKit<AopData>>,
        msg: u64,
    ) -> Result<()> {
        let size = ((msg & 0xFFFF0000) >> 16) as usize * AFK_RB_BLOCK_STEP;
        if self.iomem.is_some() {
            dev_err!(
                dev,
                "Got GetBuf message with existing buffer on endpoint {}",
                self.index
            );
            return Err(EIO);
        }
        // SAFETY: TODO
        let bound_dev = unsafe { dev.as_bound() };
        let iomem = Coherent::<u8>::zeroed_slice(bound_dev, size, GFP_KERNEL)?;
        rtkit.send_message(self.index, AFK_MSG_GET_BUF_ACK | iomem.dma_address())?;
        self.iomem = Some(iomem);
        Ok(())
    }

    fn recv_rb(&mut self, client: ArcBorrow<'_, AopData>) -> Result<()> {
        let (buf_offset, block_size, buf_size) = match self.rxbuf.as_ref() {
            Some(b) => (b.offset, b.block_size, b.buf_size),
            None => {
                dev_err!(
                    client.dev,
                    "Got Recv message with no rxbuf at endpoint {}",
                    self.index
                );
                return Err(EIO);
            }
        };
        let mut rptr = self.iomem_read32(buf_offset + block_size)? as usize;
        let mut wptr = self.iomem_read32(buf_offset + block_size * 2)?;
        mem_sync();
        let base = buf_offset + block_size * 3;
        let mut msg_buf = KVec::new();
        const QEH_SIZE: usize = mem::size_of::<QEHeader>();
        while wptr as usize != rptr {
            let mut qeh_bytes = [0; QEH_SIZE];
            self.memcpy_from_iomem(base + rptr, &mut qeh_bytes)?;
            let mut qeh = unsafe { &*(qeh_bytes.as_ptr() as *const QEHeader) };
            if qeh.magic != QE_MAGIC1 && qeh.magic != QE_MAGIC2 {
                let magic = qeh.magic;
                dev_err!(
                    client.dev,
                    "Invalid magic on ep {}, got {:x}",
                    self.index,
                    magic
                );
                return Err(EIO);
            }
            if qeh.size as usize > (buf_size - rptr - QEH_SIZE) {
                rptr = 0;
                self.memcpy_from_iomem(base + rptr, &mut qeh_bytes)?;
                qeh = unsafe { &*(qeh_bytes.as_ptr() as *const QEHeader) };

                if qeh.magic != QE_MAGIC1 && qeh.magic != QE_MAGIC2 {
                    let magic = qeh.magic;
                    dev_err!(
                        client.dev,
                        "Invalid magic on ep {}, got {:x}",
                        self.index,
                        magic
                    );
                    return Err(EIO);
                }
            }
            msg_buf.resize(qeh.size as usize, 0, GFP_KERNEL)?;
            self.memcpy_from_iomem(base + rptr + QEH_SIZE, &mut msg_buf)?;
            let (hdr_bytes, msg) = msg_buf.split_at(mem::size_of::<EPICHeader>());
            let header = unsafe { &*(hdr_bytes.as_ptr() as *const EPICHeader) };
            self.handle_ipc(client, qeh, header, msg)?;
            rptr = align_up(rptr + QEH_SIZE + qeh.size as usize, block_size) % buf_size;
            mem_sync();
            self.iomem_write32(buf_offset + block_size, rptr as u32)?;
            wptr = self.iomem_read32(buf_offset + block_size * 2)?;
            mem_sync();
        }
        Ok(())
    }
    fn handle_ipc(
        &mut self,
        client: ArcBorrow<'_, AopData>,
        qhdr: &QEHeader,
        ehdr: &EPICHeader,
        data: &[u8],
    ) -> Result<()> {
        let subtype = ehdr.subtype;
        if ehdr.category == EPIC_CATEGORY_REPORT {
            if subtype == EPIC_SUBTYPE_STD_SERVICE {
                let announce = unsafe { &*(data.as_ptr() as *const EPICServiceAnnounce) };
                let chan = announce.channel;
                let name_len = announce
                    .name
                    .iter()
                    .position(|x| *x == 0)
                    .unwrap_or(announce.name.len());
                return Into::<Arc<_>>::into(client).register_service(
                    self,
                    chan,
                    &announce.name[..name_len],
                );
            } else if subtype == EPIC_SUBTYPE_FAKEHID_REPORT {
                return client.process_fakehid_report(self, qhdr.channel, data);
            } else {
                dev_err!(
                    client.dev,
                    "Unexpected EPIC report subtype {:x} on endpoint {}",
                    subtype,
                    self.index
                );
                return Err(EIO);
            }
        } else if ehdr.category == EPIC_CATEGORY_REPLY {
            if subtype == EPIC_SUBTYPE_RETCODE_PAYLOAD
                || subtype == EPIC_SUBTYPE_RETCODE
                || subtype == EPIC_SUBTYPE_STRING
            {
                if data.len() < mem::size_of::<u32>() {
                    dev_err!(
                        client.dev,
                        "Retcode data too short on endpoint {}",
                        self.index
                    );
                    return Err(EIO);
                }
                let retcode = u32::from_ne_bytes(data[..4].try_into().unwrap());
                let tag = ehdr.tag as usize;
                if tag != 0 && tag <= self.calls.len() && self.abandoned[tag - 1] {
                    // The late reply of a call its caller gave up on: the tag is free again.
                    self.abandoned[tag - 1] = false;
                    self.call_returns[tag - 1] = None;
                    dev_dbg!(client.dev, "Late reply to an abandoned call, tag {}", tag);
                    return Ok(());
                }
                if tag == 0 || tag - 1 >= self.calls.len() || self.calls[tag - 1].is_none() {
                    dev_err!(
                        client.dev,
                        "Got a retcode with invalid tag {:?} on endpoint {}",
                        tag,
                        self.index
                    );
                    return Err(EIO);
                }
                let future = self.calls[tag - 1].take().unwrap();
                let extra_data = if let Some(mut ret) = self.call_returns[tag - 1].take() {
                    let len = cmp::min(data.len() - 4, ret.len());
                    ret[..len].copy_from_slice(&data[4..(len + 4)]);
                    ret.truncate(len);
                    Some(ret)
                } else {
                    None
                };
                future.complete(CallResult {
                    retcode,
                    extra_data,
                });

                return Ok(());
            } else {
                dev_err!(
                    client.dev,
                    "Unexpected EPIC reply subtype {:x} on endpoint {}",
                    subtype,
                    self.index
                );
                return Err(EIO);
            }
        }
        dev_err!(
            client.dev,
            "Unexpected EPIC category {:x} on endpoint {}",
            ehdr.category,
            self.index
        );
        Err(EIO)
    }
    fn send_rb(
        &mut self,
        client: &AopData,
        rtkit: Pin<&mut rtkit::RtKit<AopData>>,
        channel: u32,
        ty: u32,
        header: &[u8],
        data: &[u8],
    ) -> Result<()> {
        let (buf_offset, block_size, buf_size) = match self.txbuf.as_ref() {
            Some(b) => (b.offset, b.block_size, b.buf_size),
            None => {
                dev_err!(
                    client.dev,
                    "Attempting to send message with no txbuf at endpoint {}",
                    self.index
                );
                return Err(EIO);
            }
        };
        let base = buf_offset + block_size * 3;
        mem_sync();
        let rptr = self.iomem_read32(buf_offset + block_size)? as usize;
        let mut wptr = self.iomem_read32(buf_offset + block_size * 2)? as usize;
        const QEH_SIZE: usize = mem::size_of::<QEHeader>();
        if wptr < rptr && wptr + QEH_SIZE >= rptr {
            dev_err!(client.dev, "Tx buffer full at endpoint {}", self.index);
            return Err(EIO);
        }
        let payload_len = header.len() + data.len();
        let qeh = QEHeader {
            magic: if self.tx_magic_aop { QE_MAGIC2 } else { QE_MAGIC1 },
            size: payload_len as u32,
            channel,
            ty,
        };
        let qeh_bytes = unsafe {
            slice::from_raw_parts(
                &qeh as *const QEHeader as *const u8,
                mem::size_of::<QEHeader>(),
            )
        };
        self.memcpy_to_iomem(base + wptr, qeh_bytes)?;
        if payload_len > buf_size - wptr - QEH_SIZE {
            wptr = 0;
            self.memcpy_to_iomem(base + wptr, qeh_bytes)?;
        }
        self.memcpy_to_iomem(base + wptr + QEH_SIZE, header)?;
        self.memcpy_to_iomem(base + wptr + QEH_SIZE + header.len(), data)?;
        wptr = align_up(wptr + QEH_SIZE + payload_len, block_size) % buf_size;
        self.iomem_write32(buf_offset + block_size * 2, wptr as u32)?;
        let msg = wptr as u64 | (AFK_OPC_SEND << 48);
        rtkit.send_message(self.index, msg)
    }
    fn epic_notify(
        &mut self,
        client: &AopData,
        rtkit: Pin<&mut rtkit::RtKit<AopData>>,
        channel: u32,
        subtype: u16,
        data: &[u8],
        ret: Option<KVec<u8>>,
    ) -> Result<Arc<FutureValue<CallResult>>> {
        let mut tag = 0;
        for i in 0..self.calls.len() {
            if self.calls[i].is_none() && !self.abandoned[i] {
                tag = i + 1;
                break;
            }
        }
        if tag == 0 {
            dev_err!(
                client.dev,
                "Too many inflight calls on endpoint {}",
                self.index
            );
            return Err(EIO);
        }
        let call = Arc::pin_init(FutureValue::pin_init(), GFP_KERNEL)?;
        let hdr = EPICHeader {
            version: 2,
            seq: self.seq,
            length: data.len() as u32,
            sub_version: 2,
            category: EPIC_CATEGORY_NOTIFY,
            subtype,
            tag: tag as u16,
            ..EPICHeader::default()
        };
        self.call_returns[tag - 1] = ret;
        self.send_rb(
            client,
            rtkit,
            channel,
            EPIC_TYPE_NOTIFY,
            unsafe {
                slice::from_raw_parts(
                    &hdr as *const EPICHeader as *const u8,
                    mem::size_of::<EPICHeader>(),
                )
            },
            data,
        )?;
        self.seq = self.seq.wrapping_add(1);
        self.calls[tag - 1] = Some(call.clone());
        Ok(call)
    }
}

impl AFKEndpoint {
    /// The caller of `call` stops waiting: its slot is freed, its tag held until the reply.
    fn abandon_call(&mut self, call: &Arc<FutureValue<CallResult>>) {
        for i in 0..self.calls.len() {
            if let Some(pending) = &self.calls[i] {
                if Arc::ptr_eq(pending, call) {
                    self.calls[i] = None;
                    self.abandoned[i] = true;
                    return;
                }
            }
        }
    }
}

struct ListenerEntry {
    svc: EPICService,
    listener: Arc<dyn FakehidListener>,
}

unsafe impl Send for ListenerEntry {}

#[pin_data]
struct AopData {
    dev: ARef<device::Device>,
    #[pin]
    rtkit: Mutex<Option<rtkit::RtKit<AopData>>>,
    #[pin]
    endpoints: [Mutex<AFKEndpoint>; AFK_ENDPOINT_COUNT as usize],
    #[pin]
    ep_shutdown: FutureValue<()>,
    /// A sleep's AFK SLEEP or START answer, per endpoint
    #[pin]
    ep_sleep: [FutureValue<()>; AFK_ENDPOINT_COUNT as usize],
    /// Between a sleep's entry and its undo: new calls are refused
    sleeping: Atomic<bool>,
    /// The endpoints a sleep stopped, bit = index
    sleep_stopped: Atomic<u32>,
    /// The AP idle notice was sent and the wake notice is owed
    ap_idle: Atomic<bool>,
    /// The firmware crashed: it hears nothing more, and sleeps go on without it
    crashed: Atomic<bool>,
    #[pin]
    hid_listeners: Mutex<KVec<ListenerEntry>>,
    #[pin]
    subdevices: Mutex<KVec<*mut bindings::platform_device>>,
}

unsafe impl Send for AopData {}
unsafe impl Sync for AopData {}

#[pin_data]
struct AopServiceRegisterWork {
    name: &'static CStr,
    data: Arc<AopData>,
    service: EPICService,
    #[pin]
    work: Work<AopServiceRegisterWork>,
}

impl_has_work! {
    impl HasWork<Self, 0> for AopServiceRegisterWork { self.work }
}

impl AopServiceRegisterWork {
    fn new(
        name: &'static CStr,
        data: Arc<AopData>,
        service: EPICService,
    ) -> Result<Pin<KBox<Self>>> {
        KBox::pin_init(
            pin_init!(AopServiceRegisterWork {
                name, data, service,
                work <- new_work!("AopServiceRegisterWork::work"),
            }),
            GFP_KERNEL,
        )
    }
}

impl WorkItem for AopServiceRegisterWork {
    type Pointer = Pin<KBox<AopServiceRegisterWork>>;

    fn run(this: Pin<KBox<AopServiceRegisterWork>>) {
        let fwnode = this
            .data
            .dev
            .fwnode()
            .and_then(|x| x.get_child_by_name(this.name));
        let info = bindings::platform_device_info {
            parent: this.data.dev.as_raw(),
            name: this.name.as_ptr() as *const _,
            id: bindings::PLATFORM_DEVID_AUTO,
            res: ptr::null_mut(),
            num_res: 0,
            data: &this.service as *const EPICService as *const _,
            size_data: mem::size_of::<EPICService>(),
            dma_mask: 0,
            fwnode: fwnode.map(|x| x.as_raw()).unwrap_or(ptr::null_mut()),
            swnode: ptr::null_mut(),
            properties: ptr::null_mut(),
            of_node_reused: false,
        };
        let pdev = unsafe { from_err_ptr(bindings::platform_device_register_full(&info)) };
        match pdev {
            Err(e) => {
                dev_err!(
                    this.data.dev,
                    "Failed to create device for service {:?}: {:?}",
                    this.name,
                    e
                );
            }
            Ok(pdev) => {
                let res = this.data.subdevices.lock().push(pdev, GFP_KERNEL);
                if res.is_err() {
                    dev_err!(this.data.dev, "Failed to store subdevice");
                }
            }
        }
    }
}

impl AopData {
    fn new(dev: &platform::Device<Core<'_>>) -> Result<Arc<AopData>> {
        Arc::pin_init(
            pin_init!(
                AopData {
                    dev: dev.as_ref().into(),
                    rtkit <- new_mutex!(None),
                    endpoints <- pin_init::pin_init_array_from_fn(|i| {
                        new_mutex!(AFKEndpoint::new(AFK_ENDPOINT_START + i as u8))
                    }),
                    ep_shutdown <- FutureValue::pin_init(),
                    ep_sleep <- pin_init::pin_init_array_from_fn(|_| FutureValue::pin_init()),
                    sleeping: Atomic::new(false),
                    sleep_stopped: Atomic::new(0),
                    ap_idle: Atomic::new(false),
                    crashed: Atomic::new(false),
                    hid_listeners <- new_mutex!(KVec::new()),
                    subdevices <- new_mutex!(KVec::new()),
                }
            ),
            GFP_KERNEL,
        )
    }
    fn start(&self) -> Result<()> {
        // A firmware started (again) hasn't crashed: sleeps include it.
        self.crashed.store(false, Release);
        {
            let mut guard = self.rtkit.lock();
            let mut rtk = guard.as_mut().as_pin_mut().unwrap();
            rtk.as_mut().wake()?;
        }
        for ep in 0..AFK_ENDPOINT_COUNT {
            let rtk_ep_num = AFK_ENDPOINT_START + ep;
            let mut guard = self.rtkit.lock();
            let mut rtk = guard.as_mut().as_pin_mut().unwrap();
            if !rtk.as_mut().has_endpoint(rtk_ep_num) {
                continue;
            }
            rtk.as_mut().start_endpoint(rtk_ep_num)?;
            let ep_guard = self.endpoints[ep as usize].lock();
            ep_guard.start(rtk.as_mut())?;
        }
        Ok(())
    }
    fn register_service(
        self: Arc<Self>,
        ep: &mut AFKEndpoint,
        channel: u32,
        name: &[u8],
    ) -> Result<()> {
        let svc = EPICService {
            channel,
            endpoint: ep.index,
        };
        let dev_name = match name {
            b"aop-audio" => c_str!("audio"),
            b"las" => c_str!("las"),
            b"als" => c_str!("als"),
            _ => {
                return Ok(());
            }
        };
        // probe can call back into us, run it with locks dropped.
        let work = AopServiceRegisterWork::new(dev_name, self, svc)?;
        workqueue::system_dfl().enqueue(work);
        Ok(())
    }

    fn process_fakehid_report(&self, ep: &AFKEndpoint, ch: u32, data: &[u8]) -> Result<()> {
        let guard = self.hid_listeners.lock();
        for entry in &*guard {
            if entry.svc.endpoint == ep.index && entry.svc.channel == ch {
                return entry.listener.process_fakehid_report(data);
            }
        }
        Ok(())
    }

    fn shutdown_complete(&self) {
        self.ep_shutdown.complete(());
    }

    fn stop(&self) -> Result<()> {
        for ep in 0..AFK_ENDPOINT_COUNT {
            {
                let rtk_ep_num = AFK_ENDPOINT_START + ep;
                let mut guard = self.rtkit.lock();
                let mut rtk = guard.as_mut().as_pin_mut().unwrap();
                if !rtk.as_mut().has_endpoint(rtk_ep_num) {
                    continue;
                }
                let ep_guard = self.endpoints[ep as usize].lock();
                ep_guard.stop(rtk.as_mut())?;
            }
            self.ep_shutdown.wait();
            self.ep_shutdown.reset();
        }
        Ok(())
    }

    fn sleep_answered(&self, endpoint: u8) {
        if let Some(index) = afk_endpoint_index(endpoint) {
            self.ep_sleep[index].complete(());
        }
    }

    /// Whether RTKit has endpoint `ep`: start() started every such AFK endpoint.
    fn has_endpoint(&self, ep: u8) -> bool {
        let mut guard = self.rtkit.lock();
        match guard.as_mut().as_pin_mut() {
            Some(rtk) => rtk.has_endpoint(ep),
            None => false,
        }
    }

    /// Sends `msg` to one endpoint and waits for its answer.
    fn sleep_switch(&self, endpoint: u8, msg: u64) -> Result<()> {
        let index = afk_endpoint_index(endpoint).ok_or(EINVAL)?;
        self.ep_sleep[index].reset();
        {
            let mut guard = self.rtkit.lock();
            let rtk = guard.as_mut().as_pin_mut().ok_or(ENODEV)?;
            rtk.send_message(endpoint, msg)?;
        }
        self.ep_sleep[index]
            .wait_timeout(AFK_SLEEP_TIMEOUT_MS)
            .ok_or(ETIMEDOUT)
    }

    /// Tells the firmware about the AP's power state (RTKit's AP power ON/IDLE). Waits with
    /// the RTKit lock dropped: the answer shares a worker with messages that take it.
    fn ap_power(&self, on: bool) -> Result<()> {
        let rtk = (*self.rtkit.lock())
            .as_ref()
            .map(|rtk| rtk.as_raw())
            .ok_or(ENODEV)?;
        // SAFETY: the handle lives until removal, which holds the device lock that system
        // sleep also runs under.
        to_result(unsafe { bindings::apple_rtkit_ap_power(rtk, on) })
    }

    /// Puts back what `sleep_enter` did: the wake notice, then the stopped endpoints started.
    fn sleep_undo(&self) {
        if self.crashed.load(Acquire) {
            self.sleep_stopped.store(0, Relaxed);
            self.ap_idle.store(false, Relaxed);
            self.sleeping.store(false, Release);
            return;
        }
        let stopped = self.sleep_stopped.xchg(0, Relaxed);
        let mut still = 0u32;
        if self.ap_idle.xchg(false, Relaxed) {
            if let Err(e) = self.ap_power(true) {
                dev_err!(self.dev, "Wake notice not answered ({:?})", e);
            }
        }
        for index in 0..AFK_ENDPOINT_COUNT as usize {
            if stopped & (1 << index) == 0 {
                continue;
            }
            let endpoint = AFK_ENDPOINT_START + index as u8;
            if let Err(e) = self.sleep_switch(endpoint, AFK_MSG_START) {
                // Kept as stopped: the next sleep's undo sends its START again, and its calls
                // meanwhile fail after EPIC_CALL_TIMEOUT_MS instead of hanging.
                dev_err!(self.dev, "Endpoint {:#04x} did not restart ({:?})", endpoint, e);
                still |= 1 << index;
            }
        }
        self.sleep_stopped.store(still, Relaxed);
        self.sleeping.store(false, Release);
        if stopped != 0 {
            dev_dbg!(self.dev, "AP on notice sent and endpoints restarted after a sleep\n");
        }
    }

    /// macOS's sleep notices (the bench's AOPSEND group): one EPIC notify per endpoint, each
    /// waited for. One that isn't there, or doesn't answer, is logged and skipped. A call left
    /// unanswered keeps its tag until its answer comes (asahi's call slots have no abandon).
    fn sleep_notices(&self) {
        // SAFETY: only reads a bench switch (sleep-seq's aop_quiet).
        let quiet = unsafe { bindings::apple_sleep_bench_aop_quiet() };
        for &(ep, channel) in AOP_SLEEP_NOTICES_MACOS_T6020 {
            // aop_quiet bit 0: wakehint on its announced channel (pd633 answered 0xe00002c7 on 0).
            let channel = if ep == 0x25 && quiet & 1 != 0 {
                AOP_WAKEHINT_CHANNEL_T6020
            } else {
                channel
            };
            let Some(idx) = afk_endpoint_index(ep) else {
                continue;
            };
            if !self.has_endpoint(ep) {
                dev_info!(self.dev, "sleep notice: endpoint {:#04x} not there, skipped\n", ep);
                continue;
            }
            let call = {
                let mut rtk_guard = self.rtkit.lock();
                let Some(mut rtk) = rtk_guard.as_mut().as_pin_mut() else {
                    return;
                };
                let mut ep_guard = self.endpoints[idx].lock();
                ep_guard.tx_magic_aop = true;
                let r = ep_guard.epic_notify(
                    self,
                    rtk.as_mut(),
                    channel,
                    AOP_SLEEP_NOTICE_SUBTYPE,
                    &[0u8; AOP_SLEEP_NOTICE_LEN],
                    None,
                );
                ep_guard.tx_magic_aop = false;
                r
            };
            match call {
                Err(e) => dev_err!(self.dev, "sleep notice: endpoint {:#04x} not sent ({:?})\n", ep, e),
                Ok(call) => match call.wait_timeout(AFK_SLEEP_TIMEOUT_MS) {
                    Some(res) => dev_info!(
                        self.dev,
                        "sleep notice: endpoint {:#04x} channel {:#x} answered {:#x}\n",
                        ep,
                        channel,
                        res.retcode
                    ),
                    None => dev_err!(
                        self.dev,
                        "sleep notice: endpoint {:#04x} channel {:#x} not answered in {} ms\n",
                        ep,
                        channel,
                        AFK_SLEEP_TIMEOUT_MS
                    ),
                },
            }
        }
    }

    /// The AOP keeps running through a firmware-driven suspend: it stops its endpoints and
    /// hears the AP's power state, then the reverse after a wake, with no firmware restart
    /// (aurora, measured on T8140; native5's t6020 bench order and notices behind its groups).
    fn sleep_enter(&self) -> Result<()> {
        self.sleeping.store(true, Release);
        if self.crashed.load(Acquire) {
            dev_warn!(self.dev, "firmware crashed: sleeping without it\n");
            return Ok(());
        }
        // SAFETY: only reads flags. The bench's AOPORDER group (t6020 sleep-seq bit 62).
        let macos = unsafe { bindings::apple_sleep_bench_aop_macos_order() };
        let all: KVec<u8> = {
            let mut v = KVec::new();
            for i in 0..AFK_ENDPOINT_COUNT {
                v.push(AFK_ENDPOINT_START + i, GFP_KERNEL)?;
            }
            v
        };
        let order: &[u8] = if macos { AOP_SLEEP_ORDER_MACOS_T6020 } else { &all };
        // SAFETY: only reads flags. The bench's AOPSEND group (bit 63): macOS's notices, after
        // its first SLEEP.
        let mut notices = unsafe { bindings::apple_sleep_bench_aop_notices() };
        if notices && order.first() != Some(&0x26) {
            self.sleep_notices();
            notices = false;
        }
        let mut result = Ok(());
        for &endpoint in order {
            let Some(index) = afk_endpoint_index(endpoint) else {
                continue;
            };
            if !self.has_endpoint(endpoint) {
                continue;
            }
            // One the last undo couldn't start again is still stopped: the undo retries it.
            // Unless its START_ACK came late (it's in ep_sleep): then it runs, and is slept.
            if self.sleep_stopped.load(Relaxed) & (1 << index) != 0 {
                if self.ep_sleep[index].val.lock().is_none() {
                    continue;
                }
                self.sleep_stopped
                    .store(self.sleep_stopped.load(Relaxed) & !(1 << index), Relaxed);
            }
            // Marked before the wait: a SLEEP that went out but wasn't answered may still have
            // stopped it, so the undo STARTs every endpoint a SLEEP was sent to (rv-dpaudio).
            self.sleep_stopped
                .store(self.sleep_stopped.load(Relaxed) | (1 << index), Relaxed);
            result = self.sleep_switch(endpoint, AFK_MSG_SLEEP).inspect_err(|e| {
                dev_err!(self.dev, "Endpoint {:#04x} did not stop ({:?})", endpoint, e);
            });
            if result.is_err() {
                break;
            }
            if notices && endpoint == 0x26 {
                self.sleep_notices();
                notices = false;
            }
        }
        if notices {
            self.sleep_notices();
        }
        if result.is_ok() {
            // Set first: a notice without an answer may still have been taken.
            self.ap_idle.store(true, Relaxed);
            result = self.ap_power(false).inspect_err(|e| {
                dev_err!(self.dev, "Sleep notice not answered ({:?})", e);
            });
        }
        if result.is_err() {
            self.sleep_undo();
        } else {
            dev_dbg!(self.dev, "Endpoints stopped and AP idle notice answered for a sleep\n");
        }
        result
    }

    fn patch_bootargs(
        &self,
        aop_mmio: &Mmio<'_, Region<AOP_MMIO_SIZE>>,
        patches: &[(u32, u64)],
    ) -> Result<()> {
        let offset = aop_mmio.read32(BOOTARGS_OFFSET) as usize;
        let size = aop_mmio.read32(BOOTARGS_SIZE) as usize;
        let mut arg_bytes = KVec::<u8>::from_elem(0, size, GFP_KERNEL)?;
        let aop_io_array: Mmio<'_, [u8; AOP_MMIO_SIZE]> = aop_mmio.try_cast()?;
        let bootargs = io_project!(aop_io_array, [try: offset .. offset+size]);
        bootargs.copy_to_slice(&mut arg_bytes);
        let mut idx = 0;
        while idx < size {
            let key = u32::from_le_bytes(arg_bytes[idx..idx + 4].try_into().unwrap());
            let size = u32::from_le_bytes(arg_bytes[idx + 4..idx + 8].try_into().unwrap()) as usize;
            idx += 8;
            for (k, v) in patches.iter() {
                if *k != key {
                    continue;
                }
                arg_bytes[idx..idx + size].copy_from_slice(&(*v as u64).to_le_bytes()[..size]);
                break;
            }
            idx += size;
        }
        bootargs.copy_from_slice(&arg_bytes);
        Ok(())
    }
}

impl AopData {
    /// Waits a bounded time for the reply to `call` on endpoint `ep_idx` (aurora's wait_call).
    fn wait_call(
        &self,
        ep_idx: usize,
        svc: &EPICService,
        subtype: u16,
        call: Arc<FutureValue<CallResult>>,
    ) -> Result<CallResult> {
        if let Some(res) = call.wait_timeout(EPIC_CALL_TIMEOUT_MS) {
            return Ok(res);
        }
        self.endpoints[ep_idx].lock().abandon_call(&call);
        // The reply may have come in between: then it's ours after all.
        if let Some(res) = call.wait_timeout(0) {
            return Ok(res);
        }
        dev_err!(
            self.dev,
            "EPIC call {:#x} on channel {} timed out after {} ms",
            subtype,
            svc.channel,
            EPIC_CALL_TIMEOUT_MS
        );
        Err(ETIMEDOUT)
    }
}

impl AOP for AopData {
    fn epic_call(&self, svc: &EPICService, subtype: u16, msg_bytes: &[u8]) -> Result<u32> {
        if self.sleeping.load(Acquire) {
            return Err(EBUSY);
        }
        let ep_idx = svc.endpoint - AFK_ENDPOINT_START;
        let call = {
            let mut rtk_guard = self.rtkit.lock();
            let mut rtk = rtk_guard.as_mut().as_pin_mut().unwrap();
            let mut ep_guard = self.endpoints[ep_idx as usize].lock();
            ep_guard.epic_notify(self, rtk.as_mut(), svc.channel, subtype, msg_bytes, None)?
        };
        Ok(self.wait_call(ep_idx as usize, svc, subtype, call)?.retcode)
    }
    fn epic_call_ret(
        &self,
        svc: &EPICService,
        subtype: u16,
        msg_bytes: &[u8],
        ret_len: usize,
    ) -> Result<(u32, KVec<u8>)> {
        if self.sleeping.load(Acquire) {
            return Err(EBUSY);
        }
        let ep_idx = svc.endpoint - AFK_ENDPOINT_START;
        let call = {
            let mut rtk_guard = self.rtkit.lock();
            let mut rtk = rtk_guard.as_mut().as_pin_mut().unwrap();
            let mut ep_guard = self.endpoints[ep_idx as usize].lock();
            let mut ret_buf = KVec::new();
            ret_buf.resize(ret_len, 0, GFP_KERNEL)?;
            ep_guard.epic_notify(
                self,
                rtk.as_mut(),
                svc.channel,
                subtype,
                msg_bytes,
                Some(ret_buf),
            )?
        };
        let res = self.wait_call(ep_idx as usize, svc, subtype, call)?;
        Ok((res.retcode, res.extra_data.ok_or(EIO)?))
    }
    fn add_fakehid_listener(
        &self,
        svc: EPICService,
        listener: Arc<dyn FakehidListener>,
    ) -> Result<()> {
        let mut guard = self.hid_listeners.lock();
        Ok(guard.push(ListenerEntry { svc, listener }, GFP_KERNEL)?)
    }
    fn remove_fakehid_listener(&self, svc: &EPICService) -> bool {
        let mut guard = self.hid_listeners.lock();
        for i in 0..guard.len() {
            if guard[i].svc == *svc {
                guard.swap_remove(i);
                return true;
            }
        }
        false
    }
    fn remove(&self) {
        if let Err(e) = self.stop() {
            dev_err!(self.dev, "Failed to stop AOP {:?}", e);
        }
        self.rtkit.lock().as_mut().set(None);
        let guard = self.subdevices.lock();
        for pdev in &*guard {
            unsafe {
                bindings::platform_device_unregister(*pdev);
            }
        }
    }
}

struct NoBuffer;
impl rtkit::Buffer for NoBuffer {
    fn iova(&self) -> Result<usize> {
        unreachable!()
    }
    fn buf(&mut self) -> Result<IoSysMap<'_, Region>> {
        unreachable!()
    }
}

#[vtable]
impl rtkit::Operations for AopData {
    type Data = Arc<AopData>;
    type Buffer = NoBuffer;

    fn recv_message(data: <Self::Data as ForeignOwnable>::Borrowed<'_>, ep: u8, msg: u64) {
        let mut guard = data.rtkit.lock();
        let mut rtk = guard.as_mut().as_pin_mut().unwrap();
        let mut ep_guard = data.endpoints[(ep - AFK_ENDPOINT_START) as usize].lock();
        let ret = ep_guard.recv_message(data, rtk.as_mut(), msg);
        if let Err(e) = ret {
            dev_err!(data.dev, "Failed to handle rtkit message, error: {:?}", e);
        }
    }

    fn crashed(data: <Self::Data as ForeignOwnable>::Borrowed<'_>, _crashlog: Option<&[u8]>) {
        data.crashed.store(true, Release);
        dev_err!(data.dev, "AOP firmware crashed");
    }
}

#[repr(transparent)]
struct AopDriver(Arc<dyn AOP>);

struct AopHwConfig {
    ec0p: u64,
    alig: u64,
    aopt: u64,
}

const HW_CFG_T8103: AopHwConfig = AopHwConfig {
    ec0p: 0x020000,
    aopt: 1,
    alig: 128,
};
const HW_CFG_T8112: AopHwConfig = AopHwConfig {
    ec0p: 0x020000,
    aopt: 0,
    alig: 128,
};
const HW_CFG_T6000: AopHwConfig = AopHwConfig {
    ec0p: 0x020000,
    aopt: 0,
    alig: 64,
};
const HW_CFG_T6020: AopHwConfig = AopHwConfig {
    ec0p: 0x0100_00000000,
    aopt: 0,
    alig: 64,
};

kernel::of_device_table!(
    OF_TABLE,
    <AopDriver as platform::Driver>::IdInfo,
    [
        (of::DeviceId::new(c_str!("apple,t8103-aop")), &HW_CFG_T8103),
        (of::DeviceId::new(c_str!("apple,t8112-aop")), &HW_CFG_T8112),
        (of::DeviceId::new(c_str!("apple,t6000-aop")), &HW_CFG_T6000),
        (of::DeviceId::new(c_str!("apple,t6020-aop")), &HW_CFG_T6020),
    ]
);

/// # Safety
///
/// `dev` is a bound AOP device: its drvdata is the `AopDriver` probe returned.
unsafe fn aop_from_dev<'a>(dev: *mut bindings::device) -> &'a AopData {
    // SAFETY: by the caller's contract, drvdata is the boxed `AopDriver`.
    let driver = unsafe { &*bindings::dev_get_drvdata(dev).cast::<AopDriver>() };
    let data: *const dyn AOP = &*driver.0;
    // SAFETY: probe made this `Arc<dyn AOP>` from an `Arc<AopData>`.
    unsafe { &*data.cast::<AopData>() }
}

/// A sleep that reaches the firmware, or the bench's own switch (apple_sleep.aop_sleep). Off,
/// suspend_late returns at once and the resume finds nothing to undo: the sensors, mic and ALS
/// behave as before.
///
/// # Safety
///
/// Called by the PM core with a bound AOP device.
unsafe extern "C" fn aop_suspend_late(dev: *mut bindings::device) -> c_int {
    // SAFETY: only reads flags.
    if !unsafe { bindings::pm_suspend_via_firmware() }
        && !unsafe { bindings::apple_sleep_bench_aop_sleep() }
    {
        return 0;
    }
    // SAFETY: by this function's contract.
    match unsafe { aop_from_dev(dev) }.sleep_enter() {
        Ok(()) => 0,
        Err(e) => e.to_errno(),
    }
}

/// # Safety
///
/// Called by the PM core with a bound AOP device.
unsafe extern "C" fn aop_resume(dev: *mut bindings::device) -> c_int {
    // SAFETY: by this function's contract.
    let aop = unsafe { aop_from_dev(dev) };
    if aop.sleeping.load(Acquire) {
        aop.sleep_undo();
    }
    0
}

static AOP_PM_OPS: bindings::dev_pm_ops = bindings::dev_pm_ops {
    suspend_late: Some(aop_suspend_late),
    resume: Some(aop_resume),
    // SAFETY: all-zero is a valid `dev_pm_ops`: no callbacks.
    ..unsafe { core::mem::zeroed() }
};

impl platform::Driver for AopDriver {
    type IdInfo = &'static AopHwConfig;
    type Data<'bound> = AopDriver;

    const OF_ID_TABLE: Option<of::IdTable<Self::IdInfo>> = Some(&OF_TABLE);

    fn pm_ops() -> Option<&'static bindings::dev_pm_ops> {
        Some(&AOP_PM_OPS)
    }

    fn probe<'bound>(
        pdev: &'bound platform::Device<Core<'_>>,
        info: Option<&'bound Self::IdInfo>,
    ) -> impl PinInit<Self::Data<'bound>, Error> + 'bound {
        let cfg = info.ok_or(ENODEV)?;
        unsafe { pdev.dma_set_mask_and_coherent(DmaMask::new::<42>())? };
        let aop_req = pdev.io_request_by_index(0).ok_or(EINVAL)?;
        let aop_mmio = aop_req.iomap_sized::<AOP_MMIO_SIZE>()?;
        let asc_req = pdev.io_request_by_index(1).ok_or(EINVAL)?;
        let asc_mmio = asc_req.iomap_sized::<ASC_MMIO_SIZE>()?;
        let asc_mmio = asc_mmio.as_view().relaxed();
        let data = AopData::new(pdev)?;
        let aop_mmio = aop_mmio.as_view();
        data.patch_bootargs(
            &aop_mmio,
            &[
                (from_fourcc(b"EC0p"), cfg.ec0p),
                (from_fourcc(b"nCal"), 0x0),
                (from_fourcc(b"alig"), cfg.alig),
                (from_fourcc(b"AOPt"), cfg.aopt),
            ],
        )?;
        let rtkit = rtkit::RtKit::<AopData>::new(pdev.as_ref(), None, 0, data.clone())?;
        data.rtkit.lock().as_mut().set(Some(rtkit));
        asc_mmio.update(ASC_CPU_CONTROL, |r| r.with_const_cpu_run::<1>());
        data.start()?;
        let data = data as Arc<dyn AOP>;
        Ok(Self(data))
    }
}

impl Drop for AopDriver {
    fn drop(&mut self) {
        self.0.remove();
    }
}

unsafe impl Send for AopDriver {}

module_platform_driver! {
    type: AopDriver,
    name: "apple_aop",
    description: "AOP driver",
    license: "Dual MIT/GPL",
}
