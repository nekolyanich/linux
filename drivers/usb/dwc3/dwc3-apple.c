// SPDX-License-Identifier: GPL-2.0
/*
 * Apple Silicon DWC3 Glue driver
 * Copyright (C) The Asahi Linux Contributors
 *
 * Based on:
 *  - dwc3-qcom.c Copyright (c) 2018, The Linux Foundation. All rights reserved.
 *  - dwc3-of-simple.c Copyright (c) 2015 Texas Instruments Incorporated - https://www.ti.com
 */

#include <linux/of.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/suspend.h>
#include <linux/platform_device.h>
#include <linux/reset.h>
#include <linux/phy/phy.h>
#include <linux/version.h>

#include "glue.h"
#include "io.h"

/*
 * This platform requires a very specific sequence of operations to bring up dwc3 and its USB3 PHY:
 *
 * 1) The PHY itself has to be brought up; for this we need to know the mode (USB3,
 *    USB3+DisplayPort, USB4, etc) and the lane orientation. This happens through typec_mux_set.
 * 2) DWC3 has to be brought up but we must not touch the gadget area or start xhci yet.
 * 3) The PHY bring-up has to be finalized and dwc3's PIPE interface has to be switched to the
 *    USB3 PHY, this is done inside phy_set_mode.
 * 4) We can now initialize xhci or gadget mode.
 *
 * We can switch 1 and 2 but 3 has to happen after (1 and 2) and 4 has to happen after 3.
 *
 * And then to bring this all down again:
 *
 * 1) DWC3 has to exit host or gadget mode and must no longer touch those registers
 * 2) The PHY has to switch dwc3's PIPE interface back to the dummy backend
 * 3) The PHY itself can be shut down, this happens from typec_mux_set
 *
 * We also can't transition the PHY from one mode to another while dwc3 is up and running (this is
 * slightly wrong, some transitions are possible, others aren't but because we have no documentation
 * for this I'd rather play it safe).
 *
 * After both the PHY and dwc3 are initialized we will only ever see a single "new device connected"
 * event. If we just keep them running only the first device plugged in will ever work. XHCI's port
 * status register actually does show the correct state but no interrupt ever comes in. In gadget
 * mode we don't even get a USBDisconnected event and everything looks like there's still something
 * connected on the other end.
 * This can be partially explained because the USB2 D+/D- lines are connected through a stateful
 * eUSB2 repeater which in turn is controlled by a variant of the TI TPS6598x USB PD chip which
 * resets the repeater out-of-band everytime the CC lines are (dis)connected. This then requires a
 * PHY reset to make sure the PHY and the eUSB2 repeater state are synchronized again.
 *
 * And to make this all extra fun: If we get the order of some of this wrong either the port is just
 * broken until a phy+dwc3 reset, or it's broken until a full SoC reset (likely because we can't
 * reset some parts of the PHY), or some watchdog kicks in after a few seconds and forces a full SoC
 * reset (mostly seen this with USB4/Thunderbolt but there's clearly some watchdog that hates
 * invalid states).
 *
 * Hence there's really no good way to keep dwc3 fully up and running after we disconnect a cable
 * because then we can't shut down the PHY anymore. And if we kept the PHY running in whatever mode
 * it was until the next cable is connected we'd need to tear it all down and bring it back up again
 * anyway to detect and use the next device.
 *
 * Instead, we just shut down everything when a cable is disconnected and transition to
 * DWC3_APPLE_NO_CABLE.
 * During initial probe we don't have any information about the connected cable and can't bring up
 * the PHY properly and thus also can't fully bring up dwc3. Instead, we just keep everything off
 * and defer the first dwc3 probe until we get the first cable connected event. Until then we stay
 * in DWC3_APPLE_PROBE_PENDING.
 * Once a cable is connected we then keep track of the controller mode here by transitioning to
 * DWC3_APPLE_HOST or DWC3_APPLE_DEVICE.
 */
enum dwc3_apple_state {
	DWC3_APPLE_PROBE_PENDING, /* Before first cable connection, dwc3_core_probe not called */
	DWC3_APPLE_NO_CABLE, /* No cable connected, dwc3 suspended after dwc3_core_exit */
	DWC3_APPLE_HOST, /* Cable connected, dwc3 in host mode */
	DWC3_APPLE_DEVICE, /* Cable connected, dwc3 in device mode */
};

/**
 * struct dwc3_apple - Apple-specific DWC3 USB controller
 * @dwc: Core DWC3 structure
 * @dev: Pointer to the device structure
 * @mmio_resource: Resource to be passed to dwc3_core_probe
 * @apple_regs: Apple-specific DWC3 registers
 * @reset: Reset control
 * @role_sw: USB role switch
 * @lock: Mutex for synchronizing access
 * @state: Current state of the controller, see documentation for the enum for details
 */
struct dwc3_apple {
	struct dwc3 dwc;

	struct device *dev;
	struct resource *mmio_resource;
	void __iomem *apple_regs;

	struct reset_control *reset;
	struct usb_role_switch *role_sw;

	struct mutex lock;

	enum dwc3_apple_state state;

	/* sleep_stop: the controller stopped for a suspend to RAM, and what it was doing */
	struct notifier_block pm_nb;
	enum dwc3_apple_state sleep_state;
	bool sleep_stopped;
	bool sleep_wakeup;
};

#define to_dwc3_apple(d) container_of((d), struct dwc3_apple, dwc)

/*
 * Apple Silicon dwc3 vendor-specific registers
 *
 * These registers were identified by tracing XNU's memory access patterns and correlating them with
 * debug output over serial to determine their names. We don't exactly know what these do but
 * without these USB3 devices sometimes don't work.
 */
#define APPLE_DWC3_REGS_START 0xcd00
#define APPLE_DWC3_REGS_END 0xcdff

#define APPLE_DWC3_CIO_LFPS_OFFSET 0xcd38
#define APPLE_DWC3_CIO_LFPS_OFFSET_VALUE 0xf800f80

#define APPLE_DWC3_CIO_BW_NGT_OFFSET 0xcd3c
#define APPLE_DWC3_CIO_BW_NGT_OFFSET_VALUE 0xfc00fc0

#define APPLE_DWC3_CIO_LINK_TIMER 0xcd40
#define APPLE_DWC3_CIO_PENDING_HP_TIMER GENMASK(23, 16)
#define APPLE_DWC3_CIO_PENDING_HP_TIMER_VALUE 0x14
#define APPLE_DWC3_CIO_PM_LC_TIMER GENMASK(15, 8)
#define APPLE_DWC3_CIO_PM_LC_TIMER_VALUE 0xa
#define APPLE_DWC3_CIO_PM_ENTRY_TIMER GENMASK(7, 0)
#define APPLE_DWC3_CIO_PM_ENTRY_TIMER_VALUE 0x10

static inline void dwc3_apple_writel(struct dwc3_apple *appledwc, u32 offset, u32 value)
{
	writel(value, appledwc->apple_regs + offset - APPLE_DWC3_REGS_START);
}

static inline u32 dwc3_apple_readl(struct dwc3_apple *appledwc, u32 offset)
{
	return readl(appledwc->apple_regs + offset - APPLE_DWC3_REGS_START);
}

static inline void dwc3_apple_mask(struct dwc3_apple *appledwc, u32 offset, u32 mask, u32 value)
{
	u32 reg;

	reg = dwc3_apple_readl(appledwc, offset);
	reg &= ~mask;
	reg |= value;
	dwc3_apple_writel(appledwc, offset, reg);
}

static void dwc3_apple_setup_cio(struct dwc3_apple *appledwc)
{
	dwc3_apple_writel(appledwc, APPLE_DWC3_CIO_LFPS_OFFSET, APPLE_DWC3_CIO_LFPS_OFFSET_VALUE);
	dwc3_apple_writel(appledwc, APPLE_DWC3_CIO_BW_NGT_OFFSET,
			  APPLE_DWC3_CIO_BW_NGT_OFFSET_VALUE);
	dwc3_apple_mask(appledwc, APPLE_DWC3_CIO_LINK_TIMER, APPLE_DWC3_CIO_PENDING_HP_TIMER,
			FIELD_PREP(APPLE_DWC3_CIO_PENDING_HP_TIMER,
				   APPLE_DWC3_CIO_PENDING_HP_TIMER_VALUE));
	dwc3_apple_mask(appledwc, APPLE_DWC3_CIO_LINK_TIMER, APPLE_DWC3_CIO_PM_LC_TIMER,
			FIELD_PREP(APPLE_DWC3_CIO_PM_LC_TIMER, APPLE_DWC3_CIO_PM_LC_TIMER_VALUE));
	dwc3_apple_mask(appledwc, APPLE_DWC3_CIO_LINK_TIMER, APPLE_DWC3_CIO_PM_ENTRY_TIMER,
			FIELD_PREP(APPLE_DWC3_CIO_PM_ENTRY_TIMER,
				   APPLE_DWC3_CIO_PM_ENTRY_TIMER_VALUE));
}

static void dwc3_apple_set_ptrcap(struct dwc3_apple *appledwc, u32 mode)
{
	guard(spinlock_irqsave)(&appledwc->dwc.lock);
	dwc3_set_prtcap(&appledwc->dwc, mode, false);
}

static const struct dwc3_glue_ops dwc3_apple_keep_glue_ops;
static bool sleep_keep_hcd;

static int dwc3_apple_core_probe(struct dwc3_apple *appledwc)
{
	struct dwc3_probe_data probe_data = {};
	int ret;

	lockdep_assert_held(&appledwc->lock);
	WARN_ON_ONCE(appledwc->state != DWC3_APPLE_PROBE_PENDING);

	appledwc->dwc.dev = appledwc->dev;
	if (sleep_keep_hcd)
		appledwc->dwc.glue_ops = &dwc3_apple_keep_glue_ops;
	probe_data.dwc = &appledwc->dwc;
	probe_data.res = appledwc->mmio_resource;
	probe_data.ignore_clocks_and_resets = true;
	probe_data.skip_core_init_mode = true;
	probe_data.properties = DWC3_DEFAULT_PROPERTIES;

	ret = dwc3_core_probe(&probe_data);
	if (ret)
		return ret;

	appledwc->state = DWC3_APPLE_NO_CABLE;
	return 0;
}

static int dwc3_apple_core_init(struct dwc3_apple *appledwc)
{
	int ret;

	lockdep_assert_held(&appledwc->lock);

	switch (appledwc->state) {
	case DWC3_APPLE_PROBE_PENDING:
		ret = dwc3_apple_core_probe(appledwc);
		if (ret)
			dev_err(appledwc->dev, "Failed to probe DWC3 Core, err=%d\n", ret);
		break;
	case DWC3_APPLE_NO_CABLE:
		ret = dwc3_core_init(&appledwc->dwc);
		if (ret)
			dev_err(appledwc->dev, "Failed to initialize DWC3 Core, err=%d\n", ret);
		break;
	default:
		/* Unreachable unless there's a bug in this driver */
		WARN_ON_ONCE(1);
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int dwc3_apple_init(struct dwc3_apple *appledwc, enum dwc3_apple_state state)
{
	int ret, ret_reset;

	lockdep_assert_held(&appledwc->lock);

	/*
	 * The USB2 PHY on this platform must be configured for host or device mode while it is
	 * still powered off and before dwc3 tries to access it. Otherwise, the new configuration
	 * will sometimes only take affect after the *next* time dwc3 is brought up which causes
	 * the connected device to just not work.
	 * The USB3 PHY must be configured later after dwc3 has already been initialized.
	 */
	switch (state) {
	case DWC3_APPLE_HOST:
		phy_set_mode(appledwc->dwc.usb2_generic_phy[0], PHY_MODE_USB_HOST);
		break;
	case DWC3_APPLE_DEVICE:
		phy_set_mode(appledwc->dwc.usb2_generic_phy[0], PHY_MODE_USB_DEVICE);
		break;
	default:
		/* Unreachable unless there's a bug in this driver */
		return -EINVAL;
	}

	ret = reset_control_deassert(appledwc->reset);
	if (ret) {
		dev_err(appledwc->dev, "Failed to deassert reset, err=%d\n", ret);
		return ret;
	}

	ret = dwc3_apple_core_init(appledwc);
	if (ret)
		goto reset_assert;

	/*
	 * Now that the core is initialized and already went through dwc3_core_soft_reset we can
	 * configure some unknown Apple-specific settings and then bring up xhci or gadget mode.
	 */
	dwc3_apple_setup_cio(appledwc);

	switch (state) {
	case DWC3_APPLE_HOST:
		appledwc->dwc.dr_mode = USB_DR_MODE_HOST;
		dwc3_apple_set_ptrcap(appledwc, DWC3_GCTL_PRTCAP_HOST);
		/*
		 * This platform requires SUSPHY to be enabled here already in order to properly
		 * configure the PHY and switch dwc3's PIPE interface to USB3 PHY. The USB2 PHY
		 * has already been configured to the correct mode earlier.
		 */
		dwc3_enable_susphy(&appledwc->dwc, true);
		phy_set_mode(appledwc->dwc.usb3_generic_phy[0], PHY_MODE_USB_HOST);
		ret = dwc3_host_init(&appledwc->dwc);
		if (ret) {
			dev_err(appledwc->dev, "Failed to initialize host, ret=%d\n", ret);
			goto core_exit;
		}

		break;
	case DWC3_APPLE_DEVICE:
		appledwc->dwc.dr_mode = USB_DR_MODE_PERIPHERAL;
		dwc3_apple_set_ptrcap(appledwc, DWC3_GCTL_PRTCAP_DEVICE);
		/*
		 * This platform requires SUSPHY to be enabled here already in order to properly
		 * configure the PHY and switch dwc3's PIPE interface to USB3 PHY. The USB2 PHY
		 * has already been configured to the correct mode earlier.
		 */
		dwc3_enable_susphy(&appledwc->dwc, true);
		phy_set_mode(appledwc->dwc.usb3_generic_phy[0], PHY_MODE_USB_DEVICE);
		ret = dwc3_gadget_init(&appledwc->dwc);
		if (ret) {
			dev_err(appledwc->dev, "Failed to initialize gadget, ret=%d\n", ret);
			goto core_exit;
		}
		break;
	default:
		/* Unreachable unless there's a bug in this driver */
		WARN_ON_ONCE(1);
		ret = -EINVAL;
		goto core_exit;
	}

	appledwc->state = state;
	/*
	 * With a cable connected the core and its PHY are one live unit that only a role
	 * change or an unplug takes down. Keep system sleep from power-gating it underneath
	 * xHCI, which would then find a dead core on resume.
	 */
	dev_pm_syscore_device(appledwc->dev, true);
	return 0;

core_exit:
	dwc3_core_exit(&appledwc->dwc);
reset_assert:
	ret_reset = reset_control_assert(appledwc->reset);
	if (ret_reset)
		dev_warn(appledwc->dev, "Failed to assert reset, err=%d\n", ret_reset);

	return ret;
}

static int dwc3_apple_exit(struct dwc3_apple *appledwc)
{
	int ret = 0;

	lockdep_assert_held(&appledwc->lock);

	switch (appledwc->state) {
	case DWC3_APPLE_PROBE_PENDING:
	case DWC3_APPLE_NO_CABLE:
		/* Nothing to do if we're already off */
		return 0;
	case DWC3_APPLE_DEVICE:
		dev_pm_syscore_device(appledwc->dev, false);
		dwc3_gadget_exit(&appledwc->dwc);
		break;
	case DWC3_APPLE_HOST:
		dev_pm_syscore_device(appledwc->dev, false);
		dwc3_host_exit(&appledwc->dwc);
		break;
	}

	/*
	 * This platform requires SUSPHY to be enabled in order to properly power down the PHY
	 * and switch dwc3's PIPE interface back to a dummy PHY (i.e. no USB3 support and USB2 via
	 * a different PHY connected through ULPI).
	 */
	dwc3_enable_susphy(&appledwc->dwc, true);
	dwc3_core_exit(&appledwc->dwc);
	appledwc->state = DWC3_APPLE_NO_CABLE;

	ret = reset_control_assert(appledwc->reset);
	if (ret) {
		dev_err(appledwc->dev, "Failed to assert reset, err=%d\n", ret);
		return ret;
	}

	return 0;
}

static int dwc3_usb_role_switch_set(struct usb_role_switch *sw, enum usb_role role)
{
	struct dwc3_apple *appledwc = usb_role_switch_get_drvdata(sw);
	int ret;

	guard(mutex)(&appledwc->lock);

	/*
	 * Skip role switches if appledwc is already in the desired state. The
	 * USB-C port controller on M2 and M1/M2 Pro/Max/Ultra devices issues
	 * additional interrupts which results in usb_role_switch_set_role()
	 * calls with the current role.
	 * Ignore those calls here to ensure the USB-C port controller and
	 * appledwc are in a consistent state.
	 * This matches the behaviour in __dwc3_set_mode().
	 * Do no handle USB_ROLE_NONE for DWC3_APPLE_NO_CABLE and
	 * DWC3_APPLE_PROBE_PENDING since that is no-op anyway.
	 */
	if (appledwc->state == DWC3_APPLE_HOST && role == USB_ROLE_HOST)
		return 0;
	if (appledwc->state == DWC3_APPLE_DEVICE && role == USB_ROLE_DEVICE)
		return 0;

	/*
	 * We need to tear all of dwc3 down and re-initialize it every time a cable is
	 * connected or disconnected or when the mode changes. See the documentation for enum
	 * dwc3_apple_state for details.
	 */
	ret = dwc3_apple_exit(appledwc);
	if (ret)
		return ret;

	switch (role) {
	case USB_ROLE_NONE:
		/* Nothing to do if no cable is connected */
		return 0;
	case USB_ROLE_HOST:
		return dwc3_apple_init(appledwc, DWC3_APPLE_HOST);
	case USB_ROLE_DEVICE:
		return dwc3_apple_init(appledwc, DWC3_APPLE_DEVICE);
	default:
		dev_err(appledwc->dev, "Invalid target role: %d\n", role);
		return -EINVAL;
	}
}

static enum usb_role dwc3_usb_role_switch_get(struct usb_role_switch *sw)
{
	struct dwc3_apple *appledwc = usb_role_switch_get_drvdata(sw);

	guard(mutex)(&appledwc->lock);

	switch (appledwc->state) {
	case DWC3_APPLE_HOST:
		return USB_ROLE_HOST;
	case DWC3_APPLE_DEVICE:
		return USB_ROLE_DEVICE;
	case DWC3_APPLE_NO_CABLE:
	case DWC3_APPLE_PROBE_PENDING:
		return USB_ROLE_NONE;
	default:
		/* Unreachable unless there's a bug in this driver */
		dev_err(appledwc->dev, "Invalid internal state: %d\n", appledwc->state);
		return USB_ROLE_NONE;
	}
}

/*
 * Suspend to RAM (aurora's dwc3-apple sleep, the path for a controller without a fixed hub, by
 * function): the SoC's power cut resets the core and its PHY, and the PHY's resume_early sets
 * the PHY up again with the controller in reset (phy-apple-atc s2r_assume_cut). So stop the
 * controller before the sleep, while everything is powered, as an unplug does, and start it in
 * the role it had once the system is back: the role switch skips a set to the current role, so
 * nothing else would deassert its reset. Devices enumerate again after the wake, and a mounted
 * USB disk loses its block device (the HCD goes before the freezer). Runs before the freezer,
 * where the sleep's target isn't known yet (pm_suspend_target_state is set after these
 * notifiers), so it goes by the state "mem" means now: writing "freeze" with deep selected
 * costs a USB restart, as aurora's. PM_POST_SUSPEND follows an abandoned sleep as well. Off by default: a daily sleep keeps a connected controller out of system
 * sleep (syscore), as before.
 */
static bool sleep_stop;
module_param(sleep_stop, bool, 0444);
MODULE_PARM_DESC(sleep_stop, "Stop the controller for a suspend to RAM and start it again after (with phy-apple-atc s2r_assume_cut)");

static int dwc3_apple_pm_notify(struct notifier_block *nb, unsigned long action, void *unused)
{
	struct dwc3_apple *appledwc = container_of(nb, struct dwc3_apple, pm_nb);
	struct device *dev = appledwc->dev;
	int ret;

	guard(mutex)(&appledwc->lock);
	switch (action) {
	case PM_SUSPEND_PREPARE:
		if (pm_suspend_default_s2idle())
			break;
		appledwc->sleep_state = appledwc->state;
		if (appledwc->state != DWC3_APPLE_HOST && appledwc->state != DWC3_APPLE_DEVICE)
			break;
		ret = dwc3_apple_exit(appledwc);
		if (ret) {
			dev_err(dev, "refusing the sleep: the controller didn't stop: %d\n", ret);
			return notifier_from_errno(ret);
		}
		/* A wakeup path would keep the domain on, and it's going away. */
		appledwc->sleep_wakeup = device_may_wakeup(dev);
		device_set_wakeup_enable(dev, false);
		appledwc->sleep_stopped = true;
		break;
	case PM_POST_SUSPEND:
		if (!appledwc->sleep_stopped)
			break;
		appledwc->sleep_stopped = false;
		device_set_wakeup_enable(dev, appledwc->sleep_wakeup);
		/* A role change during the sleep went through the role switch already. */
		if (appledwc->state != DWC3_APPLE_NO_CABLE)
			break;
		ret = dwc3_apple_init(appledwc, appledwc->sleep_state);
		if (ret)
			dev_err(dev, "Failed to start after sleep, err=%d\n", ret);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

/*
 * Suspend to RAM with the host kept (sleep_keep_hcd, with sleep_stop off and phy-apple-atc's
 * s2r_assume_cut on). The glue stays a syscore device, so the xHCI device under it suspends and
 * resumes as on any platform: its suspend halts the controller and saves its state. A real
 * power cut then resets the core, its Apple registers and the PHY; the PHY's resume_early sets
 * the PHY up again in its tracked mode and leaves the core held in reset. Without this, xHCI's
 * resume found its restore failed (SRE) and started the controller over on a core that was
 * never set up again and a PIPE still on the dummy backend: running, but its next suspend
 * could not halt it (the second sleep's "Clearing Run/Stop bit failed -110", bench and NixOS).
 *
 * Here, before xHCI touches the core: a core still in reset, or out of it without the GUID
 * dwc3_core_init() wrote, lost its state; take it out of reset and set it up again the way
 * dwc3_apple_init() does, without the host (the PHYs and the xHCI device stay), then tell
 * xHCI it lost power (a positive return): xhci_resume() resets and starts the controller over,
 * and usbcore's persist resets the devices back in place, so a mounted USB disk keeps its block
 * device. A core that kept its state (s2idle, an aborted sleep) is left to xHCI's restore.
 *
 * No appledwc->lock: dpm holds the xHCI device's lock here, and a role change that takes the
 * glue's lock waits for that one to remove the host (AB-BA). A role change can't touch the core
 * before it has removed the host, which waits for this resume.
 */
module_param(sleep_keep_hcd, bool, 0444);
MODULE_PARM_DESC(sleep_keep_hcd, "Keep the xHCI host over a suspend to RAM and set the core up again after a power cut (with phy-apple-atc s2r_assume_cut, without sleep_stop)");

static int dwc3_apple_core_reinit(struct dwc3_apple *appledwc)
{
	struct dwc3 *dwc = &appledwc->dwc;
	int i, ret;

	phy_set_mode(dwc->usb2_generic_phy[0], PHY_MODE_USB_HOST);
	ret = reset_control_deassert(appledwc->reset);
	if (ret)
		return ret;
	ret = dwc3_core_init(dwc);
	if (ret)
		return ret;
	/* dwc3_core_init() took PHY references the core holds already (aurora's). */
	for (i = 0; i < dwc->num_usb3_ports; i++) {
		phy_power_off(dwc->usb3_generic_phy[i]);
		phy_exit(dwc->usb3_generic_phy[i]);
	}
	for (i = 0; i < dwc->num_usb2_ports; i++) {
		phy_power_off(dwc->usb2_generic_phy[i]);
		phy_exit(dwc->usb2_generic_phy[i]);
	}

	dwc3_apple_setup_cio(appledwc);
	dwc3_apple_set_ptrcap(appledwc, DWC3_GCTL_PRTCAP_HOST);
	dwc3_enable_susphy(dwc, true);
	/* The PHY's restore left the PIPE parked: route it to USB3 before xHCI starts. */
	ret = phy_set_mode(dwc->usb3_generic_phy[0], PHY_MODE_USB_HOST);
	if (ret)
		dev_warn(appledwc->dev, "USB3 PHY setup failed after the power cut, USB2 only: %d\n",
			 ret);
	return 0;
}

static int dwc3_apple_pre_host_resume(struct dwc3 *dwc)
{
	struct dwc3_apple *appledwc = to_dwc3_apple(dwc);
	int held, ret;
	u32 guid = 0;

	if (READ_ONCE(appledwc->state) != DWC3_APPLE_HOST)
		return 0;
	held = reset_control_status(appledwc->reset);
	if (held < 0) {
		dev_err(appledwc->dev, "keep_hcd: no reset status (%d): xHCI resumes as it is\n", held);
		return 0;
	}
	if (!held) {
		guid = dwc3_readl(dwc, DWC3_GUID);
		if (guid == LINUX_VERSION_CODE)
			return 0;
	}
	ret = dwc3_apple_core_reinit(appledwc);
	if (ret) {
		dev_err(appledwc->dev, "keep_hcd: the core didn't come back after the power cut: %d\n",
			ret);
		return ret;
	}
	dev_info(appledwc->dev, "keep_hcd: core set up again after the power cut (reset %s, GUID %#x, firmware resume %s), xHCI starts over\n",
		 held ? "held" : "released", guid, pm_resume_via_firmware() ? "yes" : "no");
	return 1;
}

static const struct dwc3_glue_ops dwc3_apple_keep_glue_ops = {
	.pre_host_resume = dwc3_apple_pre_host_resume,
};

static void dwc3_apple_pm_notifier_remove(void *data)
{
	struct dwc3_apple *appledwc = data;

	unregister_pm_notifier(&appledwc->pm_nb);
}

static int dwc3_apple_setup_role_switch(struct dwc3_apple *appledwc)
{
	struct usb_role_switch_desc dwc3_role_switch = { NULL };

	dwc3_role_switch.fwnode = dev_fwnode(appledwc->dev);
	dwc3_role_switch.set = dwc3_usb_role_switch_set;
	dwc3_role_switch.get = dwc3_usb_role_switch_get;
	dwc3_role_switch.driver_data = appledwc;
	appledwc->role_sw = usb_role_switch_register(appledwc->dev, &dwc3_role_switch);
	if (IS_ERR(appledwc->role_sw))
		return PTR_ERR(appledwc->role_sw);

	return 0;
}

static int dwc3_apple_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct dwc3_apple *appledwc;
	int ret;

	appledwc = devm_kzalloc(&pdev->dev, sizeof(*appledwc), GFP_KERNEL);
	if (!appledwc)
		return -ENOMEM;

	appledwc->dev = &pdev->dev;
	mutex_init(&appledwc->lock);

	appledwc->reset = devm_reset_control_get_exclusive(dev, NULL);
	if (IS_ERR(appledwc->reset))
		return dev_err_probe(&pdev->dev, PTR_ERR(appledwc->reset),
				     "Failed to get reset control\n");

	ret = reset_control_assert(appledwc->reset);
	if (ret) {
		dev_err(&pdev->dev, "Failed to assert reset, err=%d\n", ret);
		return ret;
	}

	appledwc->mmio_resource = platform_get_resource_byname(pdev, IORESOURCE_MEM, "dwc3-core");
	if (!appledwc->mmio_resource) {
		dev_err(dev, "Failed to get DWC3 MMIO\n");
		return -EINVAL;
	}

	appledwc->apple_regs = devm_platform_ioremap_resource_byname(pdev, "dwc3-apple");
	if (IS_ERR(appledwc->apple_regs))
		return dev_err_probe(dev, PTR_ERR(appledwc->apple_regs),
				     "Failed to map Apple-specific MMIO\n");

	/*
	 * On this platform, DWC3 can only be brought up after parts of the PHY have been
	 * initialized with knowledge of the target mode and cable orientation from typec_set_mux.
	 * Since this has not happened here we cannot setup DWC3 yet and instead defer this until
	 * the first cable is connected. See the documentation for enum dwc3_apple_state for
	 * details.
	 */
	appledwc->state = DWC3_APPLE_PROBE_PENDING;

	if (sleep_stop) {
		appledwc->pm_nb.notifier_call = dwc3_apple_pm_notify;
		ret = register_pm_notifier(&appledwc->pm_nb);
		if (ret)
			return dev_err_probe(dev, ret, "Failed to register the sleep notifier\n");
		ret = devm_add_action_or_reset(dev, dwc3_apple_pm_notifier_remove, appledwc);
		if (ret)
			return ret;
	}

	ret = dwc3_apple_setup_role_switch(appledwc);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "Failed to setup role switch\n");

	return 0;
}

static void dwc3_apple_remove(struct platform_device *pdev)
{
	struct dwc3 *dwc = platform_get_drvdata(pdev);
	struct dwc3_apple *appledwc = to_dwc3_apple(dwc);

	/* No sleep restarts a core being removed (the devm action's second unregister is a no-op) */
	if (sleep_stop)
		unregister_pm_notifier(&appledwc->pm_nb);

	guard(mutex)(&appledwc->lock);

	usb_role_switch_unregister(appledwc->role_sw);

	/*
	 * If we're still in DWC3_APPLE_PROBE_PENDING we never got any cable connected event and
	 * dwc3_core_probe was never called and there's hence no need to call dwc3_core_remove.
	 * dwc3_apple_exit can be called unconditionally because it checks the state itself.
	 */
	dwc3_apple_exit(appledwc);
	if (appledwc->state != DWC3_APPLE_PROBE_PENDING)
		dwc3_core_remove(&appledwc->dwc);
}

static const struct of_device_id dwc3_apple_of_match[] = {
	{ .compatible = "apple,t8103-dwc3" },
	{}
};
MODULE_DEVICE_TABLE(of, dwc3_apple_of_match);

static struct platform_driver dwc3_apple_driver = {
	.probe		= dwc3_apple_probe,
	.remove		= dwc3_apple_remove,
	.driver		= {
		.name	= "dwc3-apple",
		.of_match_table	= dwc3_apple_of_match,
	},
};

module_platform_driver(dwc3_apple_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sven Peter <sven@kernel.org>");
MODULE_DESCRIPTION("DesignWare DWC3 Apple Silicon Glue Driver");
