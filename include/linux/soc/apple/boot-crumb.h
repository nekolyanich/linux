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

/*
 * The suspend path's steps before the SEP's 0x4a (the +41 s reset, 2 of 3 with dcpext0's fixed
 * HDMI route): the last one written is the last step reached.
 * 0x68 PM_SUSPEND_PREPARE's notifiers done; sleep-seq's .begin: 0x69 entered, 0x6a SMC slpw,
 * 0x6b pmVC, 0x6c WKTP, 0x6d left; 0x70 in place of 0x69: the internal DCP isn't bound
 * (-62). A DCP's .suspend (by apple,dcp-index: 0 disp0, 1 dcpext0, 2 dcpext1): 0x78 + index
 * entered, 0x7b + index left. An ATC PHY's suspend_late (atcN): 0x74 + N entered; left:
 * atc0 0x6e, atc1 0x6f, atc2 0x7e, atc3 0x7f.
 * Not with sleep-seq's hybrid bit 30 alone: its crumb before cpu0's CYC_OVRD write is
 * 0x66 + N (0x66..0x71), which overlaps 0x68-0x71 here.
 */
#define ASEQ_CRUMB_PREPARE	0x68
#define ASEQ_CRUMB_BEGIN	0x69
#define ASEQ_CRUMB_BEGIN_NODCP	0x70
#define ASEQ_CRUMB_SLPW		0x6a
#define ASEQ_CRUMB_PMVC		0x6b
#define ASEQ_CRUMB_WKTP		0x6c
#define ASEQ_CRUMB_BEGIN_OUT	0x6d
#define DCP_CRUMB_SUSPEND_IN	0x78	/* + apple,dcp-index (0-2) */
#define DCP_CRUMB_SUSPEND_OUT	0x7b	/* + apple,dcp-index (0-2) */
#define ATC_CRUMB_SUSPEND_IN	0x74	/* + atc (0-3) */
static inline u8 atc_crumb_suspend_out(unsigned int atc)
{
	static const u8 out[4] = { 0x6e, 0x6f, 0x7e, 0x7f };

	return out[atc & 3];
}

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
