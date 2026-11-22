/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * Native bring-up crumbs: PMU boot_stage (0x6001) written from the SPMI controller's layer, so the
 * next boot's boot_error_stage shows how far a kernel with no console got. Native EL2 only, behind
 * spmi_apple_controller.boot_crumb=1; otherwise a no-op that returns 0. The write-only pmu_stage
 * parameter, the test-initrd's witness, is behind the same two conditions (-EPERM otherwise).
 * 0x34 SPMI controller probed, 0x33 sleep-seq probe entered, 0x35 late_initcall, 0x31/0x32 userspace.
 */
#ifndef _LINUX_SOC_APPLE_BOOT_CRUMB_H_
#define _LINUX_SOC_APPLE_BOOT_CRUMB_H_

#include <linux/errno.h>
#include <linux/kconfig.h>
#include <linux/types.h>

#if IS_REACHABLE(CONFIG_SPMI_APPLE)
int apple_spmi_boot_crumb(u8 stage);
bool apple_spmi_boot_crumb_on(void);
#else
static inline int apple_spmi_boot_crumb(u8 stage)
{
	return -ENODEV;
}

static inline bool apple_spmi_boot_crumb_on(void)
{
	return false;
}
#endif

#endif
