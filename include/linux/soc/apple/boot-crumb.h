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
 * The resume side (pm_test=devices, a refused sleep, the wake): a DCP's .resume 0xd0 + index
 * entered, 0xd3 + index left; a stopped dcpext's return: 0xd6 HDMI converter power on again,
 * 0xd7 block cycle started (0xdc its DARTs read and held, before PS off; 0xdd its PS words
 * back on, before the DART restore), 0xd8 cycle done, 0xd9 PMP request back, 0xda RTKit restart
 * started, 0xdb restart returned (warm; a cold fallback follows it).
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
#define DCP_CRUMB_RESUME_IN	0xd0	/* + apple,dcp-index (0-2) */
#define DCP_CRUMB_RESUME_OUT	0xd3	/* + apple,dcp-index (0-2) */
#define DCP_CRUMB_RET_PWREN	0xd6
#define DCP_CRUMB_RET_CYCLE	0xd7
#define DCP_CRUMB_RET_CYCLED	0xd8
#define DCP_CRUMB_RET_PMP	0xd9
#define DCP_CRUMB_RET_RTKIT	0xda
#define DCP_CRUMB_RET_RTKIT_OUT	0xdb
#define DCP_CRUMB_CYC_HELD	0xdc
#define DCP_CRUMB_CYC_PS_ON	0xdd
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
