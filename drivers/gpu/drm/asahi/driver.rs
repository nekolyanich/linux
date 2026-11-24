// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Top-level GPU driver implementation.

use kernel::{
    device::{
        Core,
        DeviceContext, //
    },
    dma::{
        Device,
        DmaMask, //
    },
    drm,
    drm::ioctl,
    of,
    platform,
    prelude::*,
    sync::{
        aref::ARef,
        Arc, //
    }, //
};

use crate::{
    debug,
    file,
    gem::AsahiObject,
    gpu,
    hw,
    regs, //
};

use kernel::macros::vtable;

pub(crate) struct AsahiDrmDriver;

/// Convenience type alias for the DRM device type for this driver.
pub(crate) type AsahiDrmDevice<Ctx = drm::Normal> = drm::Device<AsahiDrmDriver, Ctx>;

pub(crate) struct AsahiPlatformDriver;

// #[pin_data(PinnedDrop)]
pub(crate) struct AsahiPlatformDriverData<'bound> {
    // Dropped first: the sleep glue lets go of the GPU before the registration goes
    _sleep: SleepReg,
    _device: ARef<AsahiDrmDevice>,
    _reg: drm::Registration<'bound, AsahiDrmDriver>,
}

// The S2R glue (s2r.c, asahi.sleep_s2r): Tanabota notes/sleep/m2pro-73-gpu-s2r-design.md
extern "C" {
    fn asahi_s2r_register(
        dev: *mut kernel::bindings::device,
        rtk: *mut kernel::bindings::apple_rtkit,
        flags: u32,
    ) -> core::ffi::c_int;
    fn asahi_s2r_unregister(dev: *mut kernel::bindings::device);
    fn asahi_s2r_prepare(dev: *mut kernel::bindings::device) -> core::ffi::c_int;
    fn asahi_s2r_complete(dev: *mut kernel::bindings::device) -> core::ffi::c_int;
    fn asahi_s2r_kicked();
}

/// The GPU the sleep callbacks act on: one per system, set only with asahi.sleep_s2r.
static SLEEP_GPU: core::sync::atomic::AtomicPtr<Arc<dyn gpu::GpuManager>> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Holds the sleep registration for as long as the driver is bound.
struct SleepReg {
    dev: *mut kernel::bindings::device,
}

// SAFETY: Only a device pointer, used for the C calls, which lock as they need.
unsafe impl Send for SleepReg {}
// SAFETY: As above.
unsafe impl Sync for SleepReg {}

impl SleepReg {
    fn new(pdev: &platform::Device<Core<'_>>, gpu: &Arc<dyn gpu::GpuManager>) -> Result<SleepReg> {
        let flags = crate::module_parameters::sleep_s2r.value();
        let dev = pdev.as_ref().as_raw();
        if flags == 0 {
            return Ok(SleepReg { dev: core::ptr::null_mut() });
        }
        let held = KBox::into_raw(KBox::new(gpu.clone(), GFP_KERNEL)?);
        let old = SLEEP_GPU.swap(held, core::sync::atomic::Ordering::AcqRel);
        if !old.is_null() {
            // SAFETY: Came from `KBox::into_raw` above, on an earlier bind.
            drop(unsafe { KBox::from_raw(old) });
        }
        // SAFETY: `dev` is the bound device, `rtkit_raw` its live RTKit handle.
        kernel::error::to_result(unsafe { asahi_s2r_register(dev, gpu.rtkit_raw(), flags) })?;
        Ok(SleepReg { dev })
    }
}

impl Drop for SleepReg {
    fn drop(&mut self) {
        if self.dev.is_null() {
            return;
        }
        // SAFETY: The device is still bound while its driver data drops.
        unsafe { asahi_s2r_unregister(self.dev) };
        let old = SLEEP_GPU.swap(core::ptr::null_mut(), core::sync::atomic::Ordering::AcqRel);
        if !old.is_null() {
            // SAFETY: Came from `KBox::into_raw` in `SleepReg::new`.
            drop(unsafe { KBox::from_raw(old) });
        }
    }
}

struct SleepOps(kernel::bindings::dev_pm_ops);

// SAFETY: Immutable: the callbacks are plain functions.
unsafe impl Sync for SleepOps {}

/// Before any device suspends: a firmware-driven suspend arms the stop (s2r.c).
unsafe extern "C" fn sleep_prepare(dev: *mut kernel::bindings::device) -> core::ffi::c_int {
    // SAFETY: Called by the PM core for a bound device.
    unsafe { asahi_s2r_prepare(dev) }
}

/// After every device resumed: the warm restart if the stop ran, the kick, or the jobs failed.
unsafe extern "C" fn sleep_complete(dev: *mut kernel::bindings::device) {
    // SAFETY: Called by the PM core for a bound device.
    let ret = unsafe { asahi_s2r_complete(dev) };
    if ret == 0 {
        return;
    }
    let gpu = SLEEP_GPU.load(core::sync::atomic::Ordering::Acquire);
    if gpu.is_null() {
        return;
    }
    // SAFETY: Set while bound (SleepReg), and the PM core keeps the device bound here.
    let gpu = unsafe { &*gpu };
    if ret < 0 {
        gpu.mark_lost();
        return;
    }
    if gpu.kick_firmware().is_err() {
        gpu.mark_lost();
        return;
    }
    // SAFETY: Only writes the kick's crumb.
    unsafe { asahi_s2r_kicked() };
    // A HELLO alone doesn't show the firmware reads its rings: one device-control round trip
    // does (it consumes the command, or this times out), so a dead one fails jobs, not hangs.
    if let Err(e) = gpu.flush_fw_cache() {
        pr_err!("asahi: s2r: no device-control reply after the warm restart: {:?}\n", e);
        gpu.mark_lost();
    }
}

static SLEEP_OPS: SleepOps = SleepOps(kernel::bindings::dev_pm_ops {
    prepare: Some(sleep_prepare),
    complete: Some(sleep_complete),
    // SAFETY: All-zero is the absence of every other callback.
    ..unsafe { core::mem::zeroed() }
});

/// Holds a reference to the top-level `GpuManager` object.
#[pin_data]
pub(crate) struct AsahiDrmRegistrationData<'drm> {
    #[pin]
    pub(crate) gpu: Arc<dyn gpu::GpuManager>,
    pub(crate) resources: regs::Resources<'drm>,
}

/// Convenience type alias for the DRM device type for this driver.
pub(crate) type AsahiDevice = ARef<AsahiDrmDevice>;
pub(crate) type AsahiDevRef = ARef<AsahiDrmDevice>;
pub(crate) type AsahiRegData<'drm> = AsahiDrmRegistrationData<'drm>;

/// DRM Driver metadata
const INFO: drm::driver::DriverInfo = drm::driver::DriverInfo {
    major: 0,
    minor: 0,
    patchlevel: 0,
    name: c"asahi",
    desc: c"Apple AGX Graphics",
};

/// DRM Driver implementation for `AsahiDriver`.
#[vtable]
impl drm::driver::Driver for AsahiDrmDriver {
    type Data = ();
    type RegistrationData<'drm> = AsahiDrmRegistrationData<'drm>;
    /// Our `File` type.
    type File = file::File;
    /// Our `Object` type.
    type Object = drm::gem::shmem::Object<AsahiObject>;
    type ParentDevice<Ctx: DeviceContext> = platform::Device<Ctx>;

    const INFO: drm::driver::DriverInfo = INFO;
    const FEAT_RENDER: bool = true;
    const FEAT_SYNCOBJ: bool = true;
    const FEAT_SYNCOBJ_TIMELINE: bool = true;

    kernel::declare_drm_ioctls! {
        (ASAHI_GET_PARAMS,      drm_asahi_get_params,
                          ioctl::RENDER_ALLOW, crate::file::File::get_params),
        (ASAHI_GET_TIME,        drm_asahi_get_time,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::get_time),
        (ASAHI_VM_CREATE,       drm_asahi_vm_create,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::vm_create),
        (ASAHI_VM_DESTROY,      drm_asahi_vm_destroy,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::vm_destroy),
        (ASAHI_VM_BIND,         drm_asahi_vm_bind,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::vm_bind),
        (ASAHI_GEM_CREATE,      drm_asahi_gem_create,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::gem_create),
        (ASAHI_GEM_MMAP_OFFSET, drm_asahi_gem_mmap_offset,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::gem_mmap_offset),
        (ASAHI_GEM_BIND_OBJECT, drm_asahi_gem_bind_object,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::gem_bind_object),
        (ASAHI_QUEUE_CREATE,    drm_asahi_queue_create,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::queue_create),
        (ASAHI_QUEUE_DESTROY,   drm_asahi_queue_destroy,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::queue_destroy),
        (ASAHI_SUBMIT,          drm_asahi_submit,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::submit),
    }
}

// OF Device ID table.s
kernel::of_device_table!(
    OF_TABLE,
    <AsahiPlatformDriver as platform::Driver>::IdInfo,
    [
        (of::DeviceId::new(c"apple,agx-t8103"), &hw::t8103::HWCONFIG),
        (of::DeviceId::new(c"apple,agx-t8112"), &hw::t8112::HWCONFIG),
        (
            of::DeviceId::new(c"apple,agx-t6000"),
            &hw::t600x::HWCONFIG_T6000
        ),
        (
            of::DeviceId::new(c"apple,agx-t6001"),
            &hw::t600x::HWCONFIG_T6001
        ),
        (
            of::DeviceId::new(c"apple,agx-t6002"),
            &hw::t600x::HWCONFIG_T6002
        ),
        (
            of::DeviceId::new(c"apple,agx-t6020"),
            &hw::t602x::HWCONFIG_T6020
        ),
        (
            of::DeviceId::new(c"apple,agx-t6021"),
            &hw::t602x::HWCONFIG_T6021
        ),
        (
            of::DeviceId::new(c"apple,agx-t6022"),
            &hw::t602x::HWCONFIG_T6022
        ),
    ]
);

/// Platform Driver implementation for `AsahiDriver`.
impl platform::Driver for AsahiPlatformDriver {
    type IdInfo = &'static hw::HwConfig;
    const OF_ID_TABLE: Option<of::IdTable<Self::IdInfo>> = Some(&OF_TABLE);
    type Data<'bound> = AsahiPlatformDriverData<'bound>;

    fn pm_ops() -> Option<&'static kernel::bindings::dev_pm_ops> {
        Some(&SLEEP_OPS.0)
    }

    /// Device probe function.
    fn probe<'bound>(
        pdev: &'bound platform::Device<Core<'_>>,
        info: Option<&'bound Self::IdInfo>,
    ) -> impl PinInit<Self::Data<'bound>, Error> + 'bound {
        debug::update_debug_flags();

        dev_info!(pdev.as_ref(), "Probing...\n");

        let cfg = info.ok_or(ENODEV)?;

        unsafe { pdev.dma_set_mask_and_coherent(DmaMask::try_new(cfg.uat_oas)?)? };

        let resources = regs::Resources::new(pdev)?;

        // Initialize misc MMIO
        resources.init_mmio()?;

        // Start the coprocessor CPU, so UAT can initialize the handoff
        regs::Resources::start_cpu(pdev)?;

        let fwnode = pdev.as_ref().fwnode().ok_or(EIO)?;
        let compat: KVec<u32> = fwnode
            .property_read_array_vec(c"apple,firmware-compat", 3)?
            .required_by(pdev.as_ref())?;

        let drm = drm::UnregisteredDevice::<AsahiDrmDriver>::new(pdev, Ok(()))?;

        let gpu = match (cfg.gpu_gen, cfg.gpu_variant, compat.as_slice()) {
            (hw::GpuGen::G13, _, &[12, 3, 0]) => {
                gpu::GpuManagerG13V12_3::new(&drm, &resources, cfg)? as Arc<dyn gpu::GpuManager>
            }
            (hw::GpuGen::G14, hw::GpuVariant::G, &[12, 4, 0]) => {
                gpu::GpuManagerG14V12_4::new(&drm, &resources, cfg)? as Arc<dyn gpu::GpuManager>
            }
            (hw::GpuGen::G13, _, &[13, 5, 0]) => {
                gpu::GpuManagerG13V13_5::new(&drm, &resources, cfg)? as Arc<dyn gpu::GpuManager>
            }
            (hw::GpuGen::G14, hw::GpuVariant::G, &[13, 5, 0]) => {
                gpu::GpuManagerG14V13_5::new(&drm, &resources, cfg)? as Arc<dyn gpu::GpuManager>
            }
            (hw::GpuGen::G14, _, &[13, 5, 0]) => {
                gpu::GpuManagerG14XV13_5::new(&drm, &resources, cfg)? as Arc<dyn gpu::GpuManager>
            }
            _ => {
                dev_info!(
                    pdev.as_ref(),
                    "Unsupported GPU/firmware combination ({:?}, {:?}, {:?})\n",
                    cfg.gpu_gen,
                    cfg.gpu_variant,
                    compat
                );
                return Err(ENODEV);
            }
        };
        gpu.init()?;
        let sleep = SleepReg::new(pdev, &gpu)?;

        let data = try_pin_init!(AsahiDrmRegistrationData { gpu, resources });

        // SAFETY: `reg` is stored in `AsahiPlatformDriverData` and dropped when the driver is
        // unbound; it is never forgotten.
        let reg = unsafe { drm::Registration::new(pdev.as_ref(), drm, data, 0)? };

        let driver = AsahiPlatformDriverData {
            _sleep: sleep,
            _device: reg.device().into(),
            _reg: reg,
        };

        Ok(driver)
    }
}
