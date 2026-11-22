// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Apple SoC system sleep from an ordered table: T6020 (M2 Pro).
 *
 * The same contract as sleep.c (aura's /chosen/aurora,s2r-mailbox, the parking
 * spin-table CPUs of arch/arm64/kernel/smp_spin_table.c), but the last mile is
 * data: one ordered list of operations per SoC, each a register by its block
 * (the device tree's reg-names, from the ADT's /arm-io/pmgr reg[] entries) and
 * offset, a value, and the group it belongs to. The list is macOS's entry, write
 * for write, in macOS's order, as the m1n1 hypervisor recorded it (pd212, pd252).
 *
 * The SoC state an entry changes is saved as it is found, by the same list, so a
 * resume path (and later a hibernation image) can tell what to put back without
 * knowing how it was taken down; nothing here assumes DRAM survives except the
 * commit itself.
 *
 * Today only the entry exists. A dry run (apple_sleep.dry_run=1) takes every
 * step up to, and not including, the commit and the PMU, then the boot CPU's
 * deep power-down request (ACC_OVRD, CYC_OVRD | 0x3000001) and a WFI it never
 * leaves: under the m1n1 hypervisor that request is the sleep edge, where the
 * hypervisor takes over (its edge census); natively it is a hang until the
 * watchdog. The full entry (dry_run=0) adds the PMU's boot stage, the SMC
 * deadline, the PMP, both commits with the AIC mask and the RTC alarm between
 * them. With no resume path yet it runs only on the bench (apple_sleep.bench=1,
 * the hypervisor's mailbox), where the hypervisor catches the wake.
 */

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/cacheflush.h>
#include <linux/completion.h>
#include <linux/cpufreq.h>
#include <linux/cpumask.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/kernel_stat.h>
#include <linux/math64.h>
#include <linux/moduleparam.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/smp.h>
#include <linux/spmi.h>
#include <linux/suspend.h>
#include <linux/syscore_ops.h>
#include <linux/irqchip/irq-apple-aic.h>
#include <linux/mfd/macsmc.h>
#include <linux/soc/apple/sleep.h>
#include <linux/of_platform.h>
#include <linux/unaligned.h>
#include <linux/workqueue.h>
#include <clocksource/arm_arch_timer.h>
#include <asm/arch_timer.h>
#include <asm/barrier.h>
#include <asm/cpu_ops.h>
#include <asm/cputype.h>
#include <asm/daifflags.h>
#include <asm/smp_plat.h>
#include <asm/suspend.h>
#include <asm/sysreg.h>
#include <asm/virt.h>

#include <linux/soc/apple/boot-crumb.h>

#include "sleep-aura.h"

/* Core power-down sysregs, as m1n1's cpu_regs.h names them */
#define SYS_IMP_APL_CYC_OVRD		sys_reg(3, 5, 15, 5, 0)
#define CYC_OVRD_FIQ_MODE_MASK		GENMASK_ULL(21, 20)
#define CYC_OVRD_IRQ_MODE_MASK		GENMASK_ULL(23, 22)
/* WFI_MODE(3), power-gate, and DISABLE_WFI_RET: macOS's deep value, in mode 0 */
#define CYC_OVRD_DEEP			0x3000001ULL

#define SYS_IMP_APL_ACC_OVRD		sys_reg(3, 5, 15, 6, 0)
#define ACC_OVRD_PWR_DN_SRM		GENMASK_ULL(14, 13)
#define ACC_OVRD_DIS_L2_FLUSH		GENMASK_ULL(16, 15)
#define ACC_OVRD_TRAIN_DOWN_LINK	GENMASK_ULL(18, 17)
#define ACC_OVRD_POWER_DOWN_CPM		GENMASK_ULL(26, 25)
#define ACC_OVRD_DISABLE_PIO_ON_WFI	BIT_ULL(32)
#define ACC_OVRD_DEEP_SLEEP		BIT_ULL(34)

#define SYS_IMP_APL_IPI_SR_EL1		sys_reg(3, 5, 15, 1, 1)

/* pd437/pd438's sysreg dump: core registers macOS has differently at its edge (both cpu0 and cpu4) */
#define SYS_IMP_APL_HID5		sys_reg(3, 0, 15, 5, 0)
#define HID5_UNK_19_18			GENMASK_ULL(19, 18)
#define HID5_UNK19			BIT_ULL(19)
#define SYS_IMP_APL_IPI_CR_EL1		sys_reg(3, 5, 15, 3, 1)
#define IPI_CR_MACOS			0x600ULL
#define SYS_IMP_APL_SIQ_CFG_EL1		sys_reg(3, 4, 15, 10, 4)
#define SYS_IMP_APL_PMCR1_EL1		sys_reg(3, 1, 15, 1, 0)
#define SYS_IMP_APL_PMESR0_EL1		sys_reg(3, 1, 15, 5, 0)
#define SYS_IMP_APL_UPMCR0_EL1		sys_reg(3, 7, 15, 0, 4)
#define SYS_IMP_APL_UPMSR_EL1		sys_reg(3, 7, 15, 6, 4)
#define SYS_IMP_APL_UPMESR0_EL1		sys_reg(3, 7, 15, 1, 4)
#define SYS_IMP_APL_UPMESR1_EL1		sys_reg(3, 7, 15, 11, 5)
#define SYS_IMP_APL_UPMECM0_EL1		sys_reg(3, 7, 15, 3, 4)
#define SYS_IMP_APL_UPMECM1_EL1		sys_reg(3, 7, 15, 4, 4)
#define SYS_IMP_APL_UPMECM2_EL1		sys_reg(3, 7, 15, 8, 5)

/* The entry's groups, for the core register writes each core makes on its own way down */
static u64 aseq_core_groups;

/* Apple's PMU control, and the value macOS last writes before its edge (pd384) */
#define SYS_IMP_APL_PMCR0_EL1		sys_reg(3, 1, 15, 0, 0)
#define PMCR0_MACOS_EDGE		0x7003400ULL
#define IPI_SR_PENDING			BIT(0)

/* PS word */
#define PS_AUTO_ENABLE			BIT(28)
#define PS_FLAGS			GENMASK(9, 8)
#define PS_MIN				GENMASK(19, 16)
#define PS_ACTUAL			GENMASK(7, 4)
#define PS_TARGET			GENMASK(3, 0)
#define PS_ON				0xf
#define PS_POLL_US			5000

/* The PMU (j416s ADT pmu, the apple,maverick-pmic cells) */
#define PMU_BOOT_STAGE		0x6001
#define PMU_BOOT_STAGE_SLEEP	0x50
#define PMU_RTC_ALARM_CTRL	0x1401
#define PMU_RTC_ALARM_ARM	0x41	/* enable | monitor */
#define PMU_RTC_COUNTER		0x1406
#define PMU_RTC_ALARM		0x140c
#define PMU_RTC_EVENT		0x14c0
#define PMU_RTC_IRQ_MASK	0x14c2

/* A watchdog's words (WD2 at +0x20): count, bite, control; 24 MHz */
#define WDT_COUNT		0x0
#define WDT_BITE		0x4
#define WDT_CTL			0xc
#define WDT_CTL_RESET		0x4
#define WDT_TICKS_PER_S		24000000

/* The stop requests, misc-cores-offset in pmgr: write 1 to set */
#define CPU_START_STOP			0x0

/* A CPU waits this long for its turn, then goes anyway. */
#define SEQ_TURN_US			5000

/*
 * Groups, one bit each, so a bench run can leave one out at a time. The names are
 * note 24's checklist rows (notes/sleep/24-entry-trace-checklist.md in Tanabota).
 */
#define SEQ_G_SPMI	BIT(0)	/* #12 AOP SPMI notify */
#define SEQ_G_PMP	BIT(1)	/* #13-15 PMS SRAM words, PMP and PMS_SRAM off */
#define SEQ_G_DEADLINE	BIT(2)	/* #11/#19 the SMC deadline word: arms the SMC's 10 s */
#define SEQ_G_WDT	BIT(3)	/* #19 WD0 off */
#define SEQ_G_GPIOIC	BIT(4)	/* #17 AOP GPIO wake masks */
#define SEQ_G_PCIE	BIT(5)	/* #18 APCIE_GE_SYS up */
#define SEQ_G_PERF	BIT(6)	/* #20 perf-regs ← 0 */
#define SEQ_G_CLUSTER	BIT(7)	/* #21-22 ACC, CPM, DVFS, pwrgate, PMP report */
#define SEQ_G_MISC	BIT(8)	/* #23 the unnamed PMGR words (N24-A) */
#define SEQ_G_AFR	BIT(9)	/* #24 */
#define SEQ_G_CLCTL	BIT(10)	/* #25 cluster-ctl */
#define SEQ_G_SIO	BIT(11)	/* #26 */
#define SEQ_G_CLOCKS	BIT(12)	/* #27 the five muxes */
#define SEQ_G_PLL	BIT(13)	/* #28 */
#define SEQ_G_CPUS	BIT(14)	/* #16 the secondaries' stop and deep WFI */
#define SEQ_G_COMMIT	BIT(15)	/* #30/#33 the commits */
#define SEQ_G_PMU	BIT(16)	/* #11/#32 boot stage, the RTC alarm */
#define SEQ_G_AIC	BIT(17)	/* #31 every AIC line masked, between the commits */
#define SEQ_G_WD2	BIT(18)	/* #19 WD2 as macOS has it at the edge: 60 s, ctrl 4 (writer: G22) */
#define SEQ_G_WAKEMASK	BIT(19)	/* G14: pmgr[7]'s mask words as macOS's edge has them (no AP writes them) */
#define SEQ_G_GFX	BIT(20)	/* n24 #7: the GPU's CPU stopped, GFX off (macOS -534 ms) */
#define SEQ_G_DISP	BIT(21)	/* n24 #4: the three DCPs' CPUs stopped, their sys/fe/cpu0 off (-452 … -430 ms) */
#define SEQ_G_APDL	BIT(22)	/* G24: aon-misc+0x08 = 4, as macOS has it at its edge (it writes 4 at each wake) */
#define SEQ_G_LXONLY	BIT(23)	/* pd384/385: ANS's CPU stopped, the words on only in Linux off */
#define SEQ_G_MCCERR	BIT(24)	/* macOS's platform quiesce: the MCC error enables off, their status 0 */
#define SEQ_G_MCCERR_C	BIT(25)	/* the +0xc enable/status words macOS has 0 at its edge (not its quiesce's) */
#define SEQ_G_PMGRIRQ	BIT(26)	/* the PMGR interrupt status read before commit 1, as macOS's handler reads it */
#define SEQ_G_PMGRACK	BIT(27)	/* the cluster power-up events acked, as clearClusterInterruptStatus does */
#define SEQ_G_DVMFACK	BIT(28)	/* DVMF_COP (AIC 446): the status's bit 31 written back, as macOS's handler does */
#define SEQ_G_NVMEMASK	BIT(29)	/* ANS's NVMe line (AIC 1832) masked at the controller: INTMS, macOS's mask */
#define SEQ_G_PERFWAIT	BIT(30)	/* C8: each FAB/DCS perf write waits for bit 31 (busy) to clear, as _setFABPerfState does */
#define SEQ_G_N25C	BIT(31)	/* every core's +0x5008/+0x5000 and each CPM's +0x9008/+0x9000, as macOS's reset path writes */
#define SEQ_G_DVFMMAP	BIT(32)	/* the P clusters' DVFM map +0x500..0x578 <- 2..17, as macOS has it */
#define SEQ_G_THROTTLE	BIT(33)	/* CPM +0x250/+0x270/+0x8400 bit 63, set at macOS's edge */
#define SEQ_G_DISPCTL	BIT(34)	/* cluster-ctl DISPLAY 0 after C10, as macOS has it at its edge */
#define SEQ_G_HID5	BIT(35)	/* HID5 bits 19:18 = 2 (bit 19), XNU's t6020 value; m1n1's init_t6020_* sets bit 18 */
#define SEQ_G_IPICR	BIT(36)	/* IPI_CR 0x600, as macOS has it (0x1800 in Linux) */
#define SEQ_G_SIQCFG	BIT(37)	/* SIQ_CFG 0, as macOS has it (m1n1's init_cpu writes 2) */
#define SEQ_G_PMUCFG	BIT(38)	/* macOS's PMU configuration at its edge (PMCR1, PMESR0, UPMESR, UPMECM, UPMCR0) */
#define SEQ_G_APCIEEDGE	BIT(39)	/* note 32 §3: APCIE_ST_SYS on, APCIE_PHY_SW and APCIE_GP_SYS clock-gated, macOS's edge */
#define SEQ_G_MTPAUTO	BIT(40)	/* note 32 §3: the MTP island's six words AUTO, as macOS has them (Linux: AUTO off, on) */
#define SEQ_G_CLACK	BIT(41)	/* note 33 C11: each cluster-ctl write waits for bit 4 to clear, as enableCluster does */
#define SEQ_G_DCSPG	BIT(42)	/* note 32 F4, pd462/463: the 16 DCS blocks' +0x1c bit 12 set, +0x18 bit 1 clear, macOS's edge */
#define SEQ_G_AFRWAIT	BIT(43)	/* note 37: AFR's write waits for actual 0, as quiesceHW's waitReg32(map 6, 0x100, 0xf0, 0) */
#define SEQ_G_EDEEP	BIT(44)	/* note 38: cpu1-3 also take ACC_OVRD's deep fields, as macOS's E cores do */
#define SEQ_G_AFNCAUTO	BIT(45)	/* note 38 DISPLAY 1: the display fabric (afnc2_*, afnc1_lw2) AUTO, wait for actual 0 */
#define SEQ_G_CLRMW	BIT(46)	/* pd531/532: cluster-ctl written as macOS's enableCluster does, old & ~0xf (W1C bits 5/6 acked) */
#define SEQ_G_SIOGATE	BIT(47)	/* pd532/540/541: SIO's CPU stopped, SIO_CPU and SIO AUTO as macOS has them at the DISPLAY write */
#define SEQ_G_CLK15	BIT(49)	/* pd532 vs pd547: pmgr[4]+0x44000/+0x48000 bit 15, set in macOS (0x80008000) at the DISPLAY write, clear in Linux */
#define SEQ_G_PLLEARLY	BIT(48)	/* note 44: the PLL at reg[46] off as setPLLOffMode does, before cluster-ctl */
#define SEQ_G_NCORUN	BIT(50)	/* note 45: NCO channels 2/3 (pmgr[4]+0x44000/+0x48000) programmed and run as AppleS5L8960XNCO does */
#define SEQ_G_DCPREPORT	BIT(51)	/* note 46: the PMP report's display bits cleared one DCP at a time before its PS, as macOS (aurora's pmc-dcp) */
#define SEQ_G_AVEOFF	BIT(52)	/* check-in 2118: AVEMSR is off in macOS at the DISPLAY write (pd532), on in Linux (16 of 16): power it down first */
#define SEQ_G_ISPOFF	BIT(53)	/* check-in 2118: ispsens0-3 actual 4 in Linux, 0 in macOS at the DISPLAY write (ISP under DISP0_SYS) */
#define SEQ_G_DXSUB	BIT(54)	/* note 47: DISPEXT0/1 BE, GP0-2, PPP, DSC (no_ps in the ADT) on in Linux, off in macOS at the DISPLAY write */
#define SEQ_G_PGWAKE	BIT(55)	/* note 47: pwrgate page +0 (0x28e08c000) 0x80000000 in macOS (its wake writes it), 0 in Linux */
#define SEQ_G_PLLWAIT	BIT(56)	/* note 48: C14 waits for +0 bit 31 (busy) to clear, as setPLLOffMode does; Linux's PLL is still on there */
#define SEQ_G_SPMIIDLE	BIT(57)	/* note 48: nub_spmi0 auto-gated (actual 4) before C13, as macOS has it at C14 (pd577); Linux active (pd578) */
#define SEQ_G_MTPSTOP	BIT(58)	/* note 49: the MTP's CPU stopped before the DCPs, its island AUTO; Linux runs it at the commit (pd584) */
#define SEQ_G_MTPIDLE	BIT(59)	/* note 49: the MTP told AP 0x201 by its driver (rtkit-helper), as macOS, instead of MTPSTOP's CPU stop */
#define SEQ_G_PACCALL	BIT(60)	/* note 54 §10: every P core takes ACC_OVRD's deep fields, as macOS's do (pd616: 8 of 8), not only each cluster's last */
#define SEQ_G_APSCWAIT	BIT(61)	/* note 54 §11: each cluster's DVFS CMD write waits for its bit 31 (pending) to clear before and after, as AppleT6020PMGR::setPerfState's _waitAPSCPending */
#define SEQ_G_AOPORDER	BIT(62)	/* note 54 §12: with aop_sleep, the AOP's AFK endpoints get their SLEEP in macOS's order (pd154), 0x26 first, not ascending */
#define SEQ_G_AOPSEND	BIT(63)	/* note 54 §14: with aop_sleep, macOS's eight EPIC sleep notices (pd632) go to the AOP after ep 0x26's SLEEP */
#define SEQ_G_ALL	GENMASK(63, 0)

/* Never in a dry run */
#define SEQ_G_REAL	(SEQ_G_COMMIT | SEQ_G_PMU | SEQ_G_AIC | SEQ_G_WD2)

/*
 * S2R only: macOS's hibernation quiesce leaves the clusters and the PLL alone (Tanabota
 * notes/sleep/28). A hibernation entry would run this table without them.
 */
#define SEQ_G_S2R_ONLY	(SEQ_G_CLCTL | SEQ_G_PLL)

/*
 * The user's decisions (notes/sleep/26 §5.1): perf-regs skipped both ways until a commit
 * needs them. The deadline arms a reset 10 s out, and the PMP's words want a PMP driver
 * that stops it first (S1b).
 */
/* Off until measured, one at a time */
#define SEQ_G_TRIAL	(SEQ_G_WAKEMASK | SEQ_G_GFX | SEQ_G_DISP | SEQ_G_APDL | SEQ_G_LXONLY | \
			 SEQ_G_MCCERR | SEQ_G_MCCERR_C | SEQ_G_PMGRIRQ | SEQ_G_PMGRACK | \
			 SEQ_G_DVMFACK | SEQ_G_NVMEMASK | SEQ_G_PERFWAIT | SEQ_G_N25C | \
			 SEQ_G_DVFMMAP | SEQ_G_THROTTLE | SEQ_G_DISPCTL | SEQ_G_HID5 | \
			 SEQ_G_IPICR | SEQ_G_SIQCFG | SEQ_G_PMUCFG | SEQ_G_APCIEEDGE | \
			 SEQ_G_MTPAUTO | SEQ_G_CLACK | SEQ_G_DCSPG | SEQ_G_AFRWAIT | \
			 SEQ_G_EDEEP | SEQ_G_AFNCAUTO | SEQ_G_CLRMW | SEQ_G_SIOGATE | \
			 SEQ_G_PLLEARLY | SEQ_G_CLK15 | SEQ_G_NCORUN | SEQ_G_DCPREPORT | SEQ_G_AVEOFF | SEQ_G_ISPOFF | \
			 SEQ_G_DXSUB | SEQ_G_PGWAKE | SEQ_G_PLLWAIT | SEQ_G_SPMIIDLE | SEQ_G_MTPSTOP | SEQ_G_MTPIDLE | \
			 SEQ_G_PACCALL | SEQ_G_APSCWAIT | SEQ_G_AOPORDER | SEQ_G_AOPSEND)
#define SEQ_G_DEFAULT_DRY	(SEQ_G_ALL & ~(SEQ_G_PERF | SEQ_G_DEADLINE | SEQ_G_PMP | SEQ_G_TRIAL))
/* The first full entries: PMP off, it never ran in S1 (a switch, groups |= SEQ_G_PMP) */
#define SEQ_G_DEFAULT_FULL	(SEQ_G_ALL & ~(SEQ_G_PERF | SEQ_G_PMP | SEQ_G_TRIAL))
/* apple_sleep.groups left as is: the mode's default above */
#define SEQ_G_UNSET	U64_MAX

enum apple_sleep_op_kind {
	SEQ_W32,		/* val */
	SEQ_W64,		/* val */
	SEQ_CLR32,		/* read, clear the val bits, write: macOS's enable & ~mask */
	SEQ_R32,		/* read only (saved, printed): a status that may clear on read */
	SEQ_SET32,		/* read, set the val bits, write: macOS's word | bit */
	SEQ_SET64,		/* the same, 64 bits */
	SEQ_WAITCLR32,		/* poll until the val bits read 0 (SEQ_WAIT_US, a miss in ps_missed); saved[] gets the last read */
	SEQ_CLACK32,		/* as SEQ_WAITCLR32 for SEQ_CLACK_US, a miss counted in ps_missed (SEQ_CLACK_*) */
	SEQ_PS_LOWER,		/* AUTO_ENABLE off as read, then target 0 with the flags */
	SEQ_PS_RAISE_AUTO,	/* as read, target 0xf, wait for it, then AUTO_ENABLE */
	SEQ_PS_SET,		/* AUTO, PS_MIN, target from val, then wait for actual SEQ_PS_SET_ACTUAL(val) */
	SEQ_PS_NO_AUTO,		/* as read without AUTO_ENABLE */
	SEQ_PS_EDGE,		/* as SEQ_PS_SET, run when apple_sleep.edge_on has bit SEQ_PS_EDGE_BIT(val) */
	SEQ_EDGE_SET32,		/* as SEQ_SET32 with the low word, run when apple_sleep.edge_on has bit SEQ_PS_EDGE_BIT(val) */
	SEQ_EDGE_W32,		/* as SEQ_W32 with the low word, run when apple_sleep.edge_on has bit SEQ_PS_EDGE_BIT(val) */
	SEQ_DELAY,		/* val µs */
	SEQ_DEADLINE,		/* the counter in seconds + val */
	SEQ_CPUS_STOP,		/* the parked CPUs stop, one at a time, and go down */
	SEQ_BOOT_DEEP,		/* this CPU's deep power-down request and its last WFI */
	SEQ_PMU_W8,		/* PMU register off ← val, one byte (SPMI ext-write-long) */
	SEQ_PMU_R,		/* PMU register off, val bytes read and dropped, as macOS reads it */
	SEQ_PMU_RTC_NOW,	/* the PMU's RTC at off, 6 bytes, kept for SEQ_PMU_ALARM */
	SEQ_PMU_ALARM,		/* PMU register off ← the kept RTC's seconds + apple_sleep.alarm_s, 4 bytes */
	SEQ_AIC_MASK,		/* every AIC line masked */
	SEQ_MARK,		/* the counter now, for SEQ_UNTIL */
	SEQ_UNTIL,		/* wait until val µs after the last SEQ_MARK */
	SEQ_GATE,		/* val SEQ_GATE_*: if a check fails, skip to the boot CPU's power-down */
	SEQ_WD2,		/* WD2 at off: val seconds, armed with ctrl 4 */
	SEQ_ASC_STOP,		/* an ASC's CPU_CONTROL at off <- 0 twice, if its CPU's PS word (val) is not off */
	SEQ_COPROC_STOP,	/* apple,coprocs[off]'s driver idles and stops it; then as SEQ_ASC_STOP if it runs */
	SEQ_COPROC_IDLE,	/* apple,coprocs[off]'s driver's stop only; a later SEQ_COPROC_STOP of it then does nothing */
	SEQ_SEP_SLEEP,		/* the SEP driver's staged SLEEP, sent; nonzero refuses the commit */
	SEQ_CRUMB,		/* hybrid bit 28 (and bit off, if nonzero): PMU boot_stage <- val */
	SEQ_ENTRY2,		/* hybrid bit 28: BUSY-latched PS words unlatched, ANS's bridge bit 0 put back, crumbs; before commit 1 */
};

/* SEQ_ASC_STOP's val: the CPU's PS word, block and offset */
/* SEQ_WAITCLR32's bound: macOS's _setFABPerfState/_setDCSPerfState wait, 0x2ee00 µs */
#define SEQ_WAIT_US		192000
/*
 * SEQ_CLACK32: a cluster-ctl word's ack, ApplePMGR::enableCluster's waitReg32 for bit 4 (the
 * kick/busy the PMGR sets on a target change) to read 0 (note 08 §1, note 33 C11). macOS's own
 * gaps were 2.4 ms at most (EACC); the bound is ours. With SEQ_CLACK_ZERO in val, a word that
 * reads anything but 0 after the wait is written 0 and waited for once more.
 */
#define SEQ_CLACK_US		5000
#define SEQ_CLACK_BIT		BIT(4)
#define SEQ_CLACK_ZERO		BIT_ULL(32)

#define ASC_CPU_CONTROL		0x44
#define ASC_CPU_CONTROL_RUN	BIT(4)
#define ASC_CPU_STATUS		0x48
#define SEQ_PS_AT(blk, off)	((u64)(blk) << 32 | (off))
/*
 * SEQ_PS_SET's val: the word's settable bits (AUTO_ENABLE, PS_MIN, target) and, above them,
 * the actual state to wait for. The flags are written 0: they clear on a 1 only.
 */
#define SEQ_PS_SET_BITS		(PS_AUTO_ENABLE | PS_MIN | PS_TARGET)
#define SEQ_PS_SET_VAL(word, actual)	((u64)(actual) << 32 | (word))
#define SEQ_PS_SET_ACTUAL(val)	((u32)((val) >> 32) & 0xf)

/* What a gate checks: the PMU steps so far, the RTC as read against .begin's, the alarm as written */
#define SEQ_GATE_PMU		BIT(0)
#define SEQ_GATE_RTC		BIT(1)
#define SEQ_GATE_ALARM		BIT(2)
#define SEQ_GATE_SEP		BIT(3)	/* set by SEQ_SEP_SLEEP itself, not a gate's check */

struct apple_sleep_op {
	u8 kind;
	u8 blk;
	u64 group;
	u32 off;
	u64 val;
	const char *what;
};

struct apple_sleep_seq_soc {
	const char *const *blocks;
	unsigned int nblocks;
	const struct apple_sleep_op *entry;
	unsigned int nentry;
	/* The block with the stop requests, and its offset */
	u8 cpu_start_blk;
	u32 cpu_start_off;
	/* The PMU's SPMI bus (nub-spmi0) and its slave id */
	u8 pmu_blk;
	u8 pmu_sid;
	/* The commit's block: not read, not saved */
	u8 commit_blk;
	/* The SLC's enable word (MCC plane, m1n1's mcc_enable_cache), read in .begin */
	u8 slc_blk;
	u32 slc_off;
	/* Blocks read before a write only with apple_sleep.read_cluster=1, one bit each */
	u64 noread_blocks;
	/* dispext_off (note 84 §42): the external DCPs' ASC blocks, whose entry rows it runs early */
	u8 dispext_asc[2];
	u8 ndispext;
	/*
	 * The PMP report's request bit of each, cleared by read-modify-write: the table's
	 * W64 rows write macOS's whole word at the entry, which at boot would also drop
	 * the requests made since (the internal display's, the GPU's).
	 */
	u8 dispext_report_bit[2];
	u8 report_blk;
	u32 report_read, report_write, report_actual, report_status;
};

struct apple_sleep_seq {
	struct device *dev;
	const struct apple_sleep_seq_soc *soc;
	void __iomem **base;
	phys_addr_t *phys;
	struct aura_s2r_mailbox *mbox;
	/* Each entry word as the entry found it, for a resume or an image to put back */
	u64 *saved;
	bool *saved_valid;
	u64 groups;
	int cpus_stop_ret;
	int cpus_hold_ret;
	/* The PMU steps, without printing: the first failure and its step, the RTC as read */
	int pmu_ret;
	int pmu_ret_step;
	/* PS_SET, WAITCLR32, CLACK32 waits that ran out (the bench mark's bit 17, bits 39:32), the first's step */
	unsigned int ps_missed;
	int ps_missed_step;
	u64 rtc_now;
	u32 alarm;
	u64 mark;
	/* Every PMGR power word in the DT, for apple_sleep.ps_census */
	struct aseq_ps *ps;
	unsigned int nps;
	/* apple,coprocs: the devices whose drivers registered a sleep stop, and what each returned */
	struct device *coproc[5];
	int coproc_ret[5];
	/* This entry's SEQ_COPROC_IDLE ran for apple,coprocs[n] (bit n): no CPU stop for it after */
	u8 coproc_idled;
	/* dispext_off: the entry rows of the external DCPs, and whether they already ran */
	unsigned long *dispext_rows;
	/* the rows of dispext1 among them; the rest are dispext0's */
	unsigned long *dispext1_rows;
	/* bit d: dcpext<d> is in the DT, so its driver owns it: its rows never run (rv-dpswitch Q4 #1) */
	u8 dispext_bound;
	bool dispext_done;
	bool dispext_settled;
	struct delayed_work dispext_work;
	unsigned int dispext_tries;
	/* The SMC's driver, for the sleep's notices (apple_sleep.smc_notify) */
	struct device *smc_dev;
	/* The PMU through its own driver in .begin: the RTC (seconds) and the counter then */
	struct spmi_device *pmu;
	u64 rtc_begin_s;
	u64 cnt_begin;
	/* The SLC's enable word as .begin read it on cpu0 */
	u32 slc_enable;
	/* What the SEP's staged SLEEP returned, when sent */
	int sep_ret;
	/* The gate that refused, if one did (its step), and why (SEQ_GATE_*) */
	int gate_step;
	u32 gate_failed;
	/* apple_sleep.resume: boot_stage as .begin read it, the mailbox's resumes before, the PMU write after */
	u8 stage_begin;
	u64 resumes_before;
	int resume_pmu_ret;
	/* resume=2: back through cpu_resume this cycle; the PM core's stages mark RSU|4-10 */
	bool resumed;
};

static struct apple_sleep_seq *apple_sleep_seq;

static bool dry_run;
module_param(dry_run, bool, 0644);
MODULE_PARM_DESC(dry_run, "run the entry up to the commit, without PMU writes, and stop the boot CPU in its deep WFI");

static bool bench;
module_param(bench, bool, 0444);
MODULE_PARM_DESC(bench, "probe at EL1, under a hypervisor that owns the reset vectors (the m1n1 bench)");

/*
 * pd384: macOS's AOP runs at its edge, after its sleep messages (n24 rows 3: the endpoints
 * stopped, the AP idle notice 0x201). The bench doesn't flag a firmware-driven suspend, so
 * aop.rs takes that path only when asked. Needs CONFIG_APPLE_AOP (the -aop kernel).
 */
static bool aop_sleep;
module_param(aop_sleep, bool, 0644);
MODULE_PARM_DESC(aop_sleep, "the AOP takes its sleep path at suspend_late (bench only)");

/*
 * Bench (note 77 §14.20): the hybrid S3 switches of apple_sart, pinctrl_apple_gpio, spmi_apple_controller,
 * irq_apple_aic and apple_dart as one mask (APPLE_SLEEP_HYBRID_*), 1 2 4 8 0x10: the five params cost 150 bytes of a
 * 1023-byte cmdline. Each driver's own bench_hybrid still works and ORs in. Note 82's switches: 0x20 the passive
 * reads (PMP SRAM checksum, pinctrl +0xc48), 0x40 PMP SRAM kept, 0x80 +0xc48 restored, 0x100 ANS buffers kept.
 */
static uint hybrid;
module_param(hybrid, uint, 0444);

u32 apple_sleep_bench_hybrid(void)
{
	return hybrid;
}
EXPORT_SYMBOL_GPL(apple_sleep_bench_hybrid);

bool apple_sleep_bench_aop_sleep(void)
{
	return bench && aop_sleep;
}
EXPORT_SYMBOL_GPL(apple_sleep_bench_aop_sleep);

/*
 * The SEP's cmsgSLEEP (SleepType 2), sent through aurora's SEP driver: its .suspend stages it,
 * the table sends it at macOS's point (n24 row 9, before slpa). Needs CONFIG_APPLE_SEP (the
 * -sep kernel). A failure before or after the send refuses the commit.
 */
static bool sep_sleep;
module_param(sep_sleep, bool, 0644);
MODULE_PARM_DESC(sep_sleep, "send the SEP its SLEEP through its driver (bench only)");

bool apple_sleep_bench_sep_sleep(void)
{
	return bench && sep_sleep;
}
EXPORT_SYMBOL_GPL(apple_sleep_bench_sep_sleep);

/*
 * The early variant (aurora #1664 on T6041, JJRPF R18/R18F on T6020): the SEP's SLEEP sent by
 * its driver at device suspend, in process context with its DART live, the answer waited for,
 * the outbox's receive enable cleared; its gating waited for in suspend_noirq. The table's
 * SEP_SLEEP step stays with sep_sleep: use one or the other.
 */
static bool sep_sleep_early;
module_param(sep_sleep_early, bool, 0644);
MODULE_PARM_DESC(sep_sleep_early, "the SEP's SLEEP at device suspend, through its driver (bench only)");

bool apple_sleep_bench_sep_sleep_early(void)
{
	return bench && sep_sleep_early && !sep_sleep;
}
EXPORT_SYMBOL_GPL(apple_sleep_bench_sep_sleep_early);

static struct device *aseq_sep_early_dev;

void apple_sleep_sep_early_set(struct device *dev, bool wired)
{
	if (wired)
		WRITE_ONCE(aseq_sep_early_dev, dev);
	else if (READ_ONCE(aseq_sep_early_dev) == dev)
		WRITE_ONCE(aseq_sep_early_dev, NULL);
}
EXPORT_SYMBOL_GPL(apple_sleep_sep_early_set);

bool apple_sleep_sep_early_wired(void)
{
	return READ_ONCE(aseq_sep_early_dev);
}
EXPORT_SYMBOL_GPL(apple_sleep_sep_early_wired);

/* For sleep.c's co-processor registry, which refuses below EL2 off the bench */
bool apple_sleep_seq_bench(void)
{
	return bench;
}

/*
 * pd335: the "now" read of E ACC (cluster + 0x20660) trapped and the bench's HV couldn't
 * take it. macOS writes the cluster's ACC, CPM and DVFS words without reading them first, so
 * by default neither the plan nor the run reads them; their saved[] stays invalid.
 */
static bool read_cluster;
module_param(read_cluster, bool, 0644);
MODULE_PARM_DESC(read_cluster, "read the clusters' ACC, CPM and DVFS words before writing them (in the plan and the run)");

static ulong seq_groups = SEQ_G_UNSET;

/* A mask with bits no group has is a typo: said once per write, then run as given. */
static int aseq_groups_set(const char *val, const struct kernel_param *kp)
{
	int ret = param_set_ulong(val, kp);
	u64 g = *(ulong *)kp->arg;

	if (!ret && g != SEQ_G_UNSET && (g & ~(u64)SEQ_G_ALL))
		pr_warn("apple_sleep.groups=%#llx: bits %#llx are no group (known %#llx)\n",
			g, g & ~(u64)SEQ_G_ALL, (u64)SEQ_G_ALL);
	return ret;
}

/* For aop.rs: AOPORDER, read from the groups as given (only a full entry on the bench sets them) */
bool apple_sleep_bench_aop_macos_order(void)
{
	return bench && aop_sleep && seq_groups != SEQ_G_UNSET && (seq_groups & SEQ_G_AOPORDER);
}
EXPORT_SYMBOL_GPL(apple_sleep_bench_aop_macos_order);

/*
 * note 54 §15, the groups word being full: bench switches for the AOP's sleep, read by aop.rs.
 * Bit 0: AOPSEND's wakehint notice (ep 0x25) goes on its announced service channel 0x10000001, not macOS's 0
 * (pd633: 0xe00002c7 on 0).
 */
static uint aop_quiet;
module_param(aop_quiet, uint, 0644);
MODULE_PARM_DESC(aop_quiet, "bench AOP sleep switches (bit 0: wakehint notice on its service channel)");

u32 apple_sleep_bench_aop_quiet(void)
{
	return bench && aop_sleep ? aop_quiet : 0;
}
EXPORT_SYMBOL_GPL(apple_sleep_bench_aop_quiet);

/* For aop.rs: AOPSEND, the same way */
bool apple_sleep_bench_aop_notices(void)
{
	return bench && aop_sleep && seq_groups != SEQ_G_UNSET && (seq_groups & SEQ_G_AOPSEND);
}
EXPORT_SYMBOL_GPL(apple_sleep_bench_aop_notices);

static const struct kernel_param_ops aseq_groups_ops = {
	.set = aseq_groups_set,
	.get = param_get_ulong,
};
module_param_cb(groups, &aseq_groups_ops, &seq_groups, 0644);
MODULE_PARM_DESC(groups, "the entry's groups to run, one bit each (sleep-seq.c SEQ_G_*); unset: the mode's default");

/*
 * pd336: Linux's gaps after cluster-ctl EACC and around SIO came out at macOS's gap plus the
 * delay, as if macOS's gaps were the cost of running there and not waits. 0 drops the delays.
 */
static bool delays = true;
module_param(delays, bool, 0644);
MODULE_PARM_DESC(delays, "take the cluster-ctl and SIO delays (macOS's gaps, N24-E)");

/* macOS's commit 1 to commit 2 (pd252), the AIC and the alarm between them */
#define SEQ_COMMIT_GAP_US	520

/* The RTC at the commit against .begin's plus the time between: a sanity check (SID, units), not a clock */
#define SEQ_RTC_SLACK_S		10

/*
 * macOS has the SLC off at the edge (pd333: mcc[2]+0x1c00 = 0); this table has no MCC row
 * yet. Until its sequence is traced, a full entry runs only when told the SLC is acceptable.
 */
static bool slc_ok;
module_param(slc_ok, bool, 0644);
MODULE_PARM_DESC(slc_ok, "run the full entry with the SLC on (macOS turns it off; no row yet)");

/*
 * pd341: the console stops at cpu_pm_suspend, and a reset takes the rest. The bench HV keeps
 * the last 64 guest marks (`hvc #0x5332`, x0 = 4, x1 = the tag) with their time and CPU.
 */
static bool marks;
module_param(marks, bool, 0644);
MODULE_PARM_DESC(marks, "mark each entry step to the bench hypervisor (hvc #0x5332); bench only");

/* A mark's tag: "SEQ", the gate's failed checks, whether a PMU step failed, the step */
#define SEQ_MARK_MAGIC		(0x534551ULL << 40)

/*
 * pd341: an SMC reset 11.4 s after the edge, with the SMC never told. macOS tells it in the
 * device round (MBSE = slpw at -852 ms, WKTP = 2 at -561 ms) and just before the deadline word
 * (MBSE = slpa at -115.5 ms, the AP idle notice 0x201 at -115.1, the deadline at -114.9; pd252).
 * Bit 0: slpw in .begin, slpa and the notice in .prepare_late, the last point that may sleep,
 * a few ms before .enter's deadline. Bit 1: WKTP = 2 after slpw. Not pm_set_suspend_via_firmware():
 * that would turn every other driver's firmware path on too, the SEP's included.
 */
/*
 * Outside review 11-15 (Tanabota note 55): ~25 drivers take their s2idle branch on the bench.
 * A switch to try the firmware path in all of them; build without the SEP driver.
 */
static bool via_firmware;
module_param(via_firmware, bool, 0644);
MODULE_PARM_DESC(via_firmware, "bench: pm_set_suspend_via_firmware() in .begin: refused with a bound SEP driver unless the SEP takes its reviewed early or table SLEEP");

#define SEQ_SMC_SLEEP		BIT(0)
#define SEQ_SMC_WKTP		BIT(1)
/* notes 02/04: macOS writes pmVC = 0x00010000 (function-toggle_vdd_cio) between slpw and WKTP; aurora sends pmVC on every SoC */
#define SEQ_SMC_PMVC		BIT(2)
/* 8: the SMC's driver writes pmVC again at the wake, after waka (macOS toggles vdd_cio at the entry and the wake) */
#define SEQ_SMC_PMVC_WAKE	BIT(3)
/* 16: no MBSE = slpa at the entry (slpw, WKTP, pmVC and the AP idle notice 0x201 stay) */
#define SEQ_SMC_NO_SLPA		BIT(4)
/* 32/64/128: the SMC's driver, after waka at the wake: the mgmt IOP_PWR_STATE 0x9 message / WKTP = 0 twice / gp03 cycle (macOS's wake) */
static uint smc_notify;
module_param(smc_notify, uint, 0644);
MODULE_PARM_DESC(smc_notify, "tell the SMC as macOS does: 1 slpw/slpa/0x201, 2 also WKTP = 2, 4 also pmVC (apple_sleep.pmvc), 8 pmVC again at the wake, after waka, 16 no MBSE = slpa (the 0x201 notice stays), 32 IOP_PWR_STATE 0x9 to the SMC at the wake, 64 WKTP = 0 twice at the wake, 128 gp03 cycle at the end of the SMC wake");

/*
 * pmVC's value, written as a little-endian ui32. Note 02's "0x00010000" was the tracer's raw hex (data.hex()):
 * macOS's bytes are 00 01 00 00, i.e. 0x100, as Ante042 and JJRPF (worklog 3073) write it. The default keeps the
 * value every run so far sent (bytes 00 00 01 00), so older lines stay what they were; B1 sets 0x100.
 */
static uint pmvc = 0x00010000;
module_param(pmvc, uint, 0644);

/* pmVC's value at the wake (smc_notify bit 3); 0xffffffff: the entry's */
static uint pmvc_wake = U32_MAX;
module_param(pmvc_wake, uint, 0644);
MODULE_PARM_DESC(pmvc_wake, "pmVC's value written at the wake (smc_notify bit 3); 0xffffffff = apple_sleep.pmvc");

/*
 * pd647-660: at macOS's commit GPIO (0xff) and SIO_CPU (0xf0002ff) are on, PMS and
 * DEBUG_SWITCH hold PS_MIN f (0x1f0f00ff); in Linux GPIO and SIO_CPU are off, PS_MIN 0.
 * Bit 0 GPIO, bit 1 SIO_CPU, bit 2 PMS and DEBUG_SWITCH, each set at macOS's C12.
 */
/* note 65: WD2's bite in seconds instead of the table's (60): tells WD2 from the engine's own ~60 s */
static uint wd2_s;
module_param(wd2_s, uint, 0644);
MODULE_PARM_DESC(wd2_s, "bench: WD2 bite in seconds instead of 60 (<= 170)");

/*
 * native11 (pdD19, notes/sleep/86): what macOS does at its wake before the SMC's AP ON (63 ms) and Linux never
 * does, each in aseq_resumed before the boot_stage write and before any device resume. Bit 0 (25 ms): the dwi
 * PS word on (0x44, 0x4f, 0x1000004f), and only once it reads actual f, the DWI block's five writes (+0 <- 1,
 * +0xd0 <- 0x2ee00, +4 <- 0x78, +0x84 <- 0, +0x80 <- 0x41); the PS word stays on. Bit 1 (57 ms): nub-spmi0 and
 * nub-spmi1 +0x40 NOTIFY_ENABLE <- 0x3f803031. Bit 2 (61 ms): PMU boot_stage <- 0x00 instead of stage_begin.
 * The DWI block is never read (do-not-read while its PS is gated, b2aa); all mappings are non-posted.
 */
static uint wake_pmu;
module_param(wake_pmu, uint, 0644);
MODULE_PARM_DESC(wake_pmu, "bench: macOS's pre-AP-ON wake writes: 1 dwi PS on + the DWI command, 2 nub-spmi0/1 NOTIFY_ENABLE <- 0x3f803031, 4 PMU boot_stage <- 0");
#define ASEQ_WAKE_PMU_DWI	BIT(0)
#define ASEQ_WAKE_PMU_NOTIFY	BIT(1)
#define ASEQ_WAKE_PMU_STAGE0	BIT(2)
static void aseq_wake_pmu_map(void);

static uint edge_on;
module_param(edge_on, uint, 0644);
MODULE_PARM_DESC(edge_on, "bench: PS words to macOS's commit state after C12: 1 GPIO, 2 SIO_CPU, 4 PMS/DEBUG_SWITCH PS_MIN, 8 SIO children off, 16 AFNC2 LW1/LS/IOA off, 32 SIO_CPU and SIO off, 64 SIO children on as macOS, 128 perf-regs[8] enables as macOS, 256 start the perf-regs[8] counters at .begin, 512 asio fabric words 0x8004 -> 0x4 as macOS, 1024/2048 SIO/SEP axi2af bridge tunables, 4096 APCIE AUTO, DWI and UART1-6 as macOS, 8192 EDPRCR <- 0 on every core, 16384 aon-misc+8 <- 0 before commit 1, 32768 the SMC deadline <- 0 before commit 1, 65536 nub-spmi0 PMU/btm source enables as macOS, 131072 nub-spmi0 NOTIFY_ENABLE as macOS, 262144 no alarm read-back before commit 2, 524288 nub-spmi1 NOTIFY_ENABLE as macOS");
#define SEQ_PS_EDGE_VAL(bit, word, actual)	((u64)(bit) << 40 | SEQ_PS_SET_VAL(word, actual))
#define SEQ_PS_EDGE_BIT(val)			(((val) >> 40) & 0x1f)

/* macOS's gaps on t6020 (pd252): slpa to the notice 0.4 ms, the notice to the deadline 0.3 ms, round trips included */
#define SEQ_SMC_ARM_US		0
#define SEQ_SMC_IDLE_US		0

/*
 * pd341-354: the engine takes the commit (pd342) and the SoC stays up until the SMC's deadline.
 * On T8140 aurora found that a co-processor left running at the commit holds the engine. macOS
 * stops t6020's (AOP, the DCPs, GFX, PMP: note 24 rows 1-10, 14-15) and Linux's S2 path stops
 * none. This prints every power word still on just before the CPUs go, to name them.
 */
static bool ps_census;
module_param(ps_census, bool, 0644);
MODULE_PARM_DESC(ps_census, "print every PMGR power word still on at .prepare_late (read only)");

struct aseq_ps {
	const char *name;
	void __iomem *reg;
};

/*
 * pd384/385: at macOS's edge cpu0 has CNTV enabled, unmasked and fired (ctl 0x5, a virtual FIQ
 * pending) and PMCR0 last written 0x7003400; Linux masks both timers and never writes PMCR0.
 * This leaves cpu0's last step as macOS's. The secondaries keep their masked timers.
 */
static bool edge_timer;
module_param(edge_timer, bool, 0644);
MODULE_PARM_DESC(edge_timer, "cpu0's edge as macOS's: CNTV armed and fired, PMCR0 = 0x7003400");

/*
 * Native S2R (note 86 rows 2-4), each replacement of the HV's work behind its own apple_sleep.hybrid
 * bit, so a control and every rung run the same image:
 * 21 hold: the stopped CPUs go down only after commit 2 (BOOT_DEEP), cpu0 last; off: right after the
 *    stop, for the HV's DEFER_EDGE to hold;
 * 22 secondary quench before the deep request: timer CTLs 0, IPI_SR ack, PMCR0 counters/IMODE/IACT
 *    clear, UPMCR0/UPMSR 0 (hv_enter_secondary);
 * 23 cpu0 quench: a fired timer gets IMASK (ENABLE stays), IPI_SR ack, PMCR0 IACT clear (silent_quench);
 * 24 edge_cntpct written to the mailbox last before cpu0's deep request.
 * Registers written: CNTP/CNTV_CTL_EL0 (EL1: the guest's; EL2: the hypervisor-owned ones) and the
 * _EL02 views at EL2 only, IPI_SR_EL1, PMCR0_EL1, UPMCR0_EL1, UPMSR_EL1.
 */
#define ASEQ_HYBRID_NATIVE_HOLD		BIT(21)
#define ASEQ_HYBRID_NATIVE_QUENCH_SEC	BIT(22)
#define ASEQ_HYBRID_NATIVE_QUENCH_BOOT	BIT(23)
#define ASEQ_HYBRID_NATIVE_EDGE_CNTPCT	BIT(24)

#define PMCR0_CNT_MASK_NATIVE	(GENMASK_ULL(7, 0) | GENMASK_ULL(33, 32))
#define PMCR0_IMODE_NATIVE	GENMASK_ULL(10, 8)
#define PMCR0_IACT_NATIVE	BIT_ULL(11)
#define SEQ_CTL_ISTATUS		BIT(2)

/* Secondaries committed to the power-down (stop written) and those at their last WFI */
static atomic_t aseq_stopped = ATOMIC_INIT(0);
static atomic_t aseq_down = ATOMIC_INIT(0);
/* what cpu0 wrote to mbox->edge_cntpct (the boot object clears it at the wake) */
static u64 aseq_edge_cntpct;

/*
 * As the HV's silent_quench (cpu0, fired timers only) and hv_enter_secondary (a secondary: all
 * off). A pending timer, IPI or PMI would end or refuse the gated WFI.
 */
static void aseq_quench(bool boot)
{
	u64 pmcr0, fired = SEQ_CTL_ISTATUS | ARCH_TIMER_CTRL_ENABLE;
	u32 h = READ_ONCE(hybrid);

	if (!(h & (boot ? ASEQ_HYBRID_NATIVE_QUENCH_BOOT : ASEQ_HYBRID_NATIVE_QUENCH_SEC)))
		return;

	if (boot) {
		u64 v;

		if (is_kernel_in_hyp_mode()) {
			v = read_sysreg_s(SYS_CNTV_CTL_EL02);
			if ((v & fired) == fired)
				write_sysreg_s(v | ARCH_TIMER_CTRL_IT_MASK, SYS_CNTV_CTL_EL02);
			v = read_sysreg_s(SYS_CNTP_CTL_EL02);
			if ((v & fired) == fired)
				write_sysreg_s(v | ARCH_TIMER_CTRL_IT_MASK, SYS_CNTP_CTL_EL02);
		} else {
			v = read_sysreg(cntv_ctl_el0);
			if ((v & fired) == fired)
				write_sysreg(v | ARCH_TIMER_CTRL_IT_MASK, cntv_ctl_el0);
			v = read_sysreg(cntp_ctl_el0);
			if ((v & fired) == fired)
				write_sysreg(v | ARCH_TIMER_CTRL_IT_MASK, cntp_ctl_el0);
		}
	} else {
		write_sysreg(0, cntv_ctl_el0);
		write_sysreg(0, cntp_ctl_el0);
		if (is_kernel_in_hyp_mode()) {
			write_sysreg_s(0, SYS_CNTV_CTL_EL02);
			write_sysreg_s(0, SYS_CNTP_CTL_EL02);
		}
	}

	if (read_sysreg_s(SYS_IMP_APL_IPI_SR_EL1) & IPI_SR_PENDING)
		write_sysreg_s(IPI_SR_PENDING, SYS_IMP_APL_IPI_SR_EL1);

	pmcr0 = read_sysreg_s(SYS_IMP_APL_PMCR0_EL1);
	if (boot) {
		if (pmcr0 & PMCR0_IACT_NATIVE)
			write_sysreg_s(pmcr0 & ~PMCR0_IACT_NATIVE, SYS_IMP_APL_PMCR0_EL1);
	} else {
		write_sysreg_s(pmcr0 & ~(PMCR0_CNT_MASK_NATIVE | PMCR0_IMODE_NATIVE | PMCR0_IACT_NATIVE),
			       SYS_IMP_APL_PMCR0_EL1);
		write_sysreg_s(0, SYS_IMP_APL_UPMCR0_EL1);
		write_sysreg_s(0, SYS_IMP_APL_UPMSR_EL1);
	}
	isb();
}

static uint alarm_s = 30;
module_param(alarm_s, uint, 0644);
MODULE_PARM_DESC(alarm_s, "the PMU RTC alarm, seconds after the entry (the full entry only)");

/*
 * Tanabota note 77, S3 on the bench: the entry runs as cpu_suspend()'s finisher with the
 * mailbox's resume_pa = cpu_resume, so a hypervisor that enters resume_pa at the wake
 * (m1n1 v31's SLEEP_RESUME_LINUX_RESUME) comes back here. Then two witnesses that outlast a
 * reset: a bench mark, and the PMU's boot_stage back to .begin's value (the next boot reads it
 * as boot_error_stage instead of the entry's 0x50). 1: then cpu0 stays here, interrupts off,
 * one mark a second; 2: then back to the PM core (AIC masks, CPU books, timer control).
 */
static uint resume;
module_param(resume, uint, 0644);
MODULE_PARM_DESC(resume, "bench S3: 1 enter through cpu_suspend with resume_pa, after the wake the witnesses and cpu0 parked; 2 the same, then back to the PM core");

/* Bench (review 8 §5 B): RSU|10 comes this many s after PM_POST_SUSPEND, so an AT_RSU=10 stop lets slow resumes finish */
static uint alive_s = 5;
module_param(alive_s, uint, 0644);

/*
 * A resume mark's tag: "RSU", then the step (1 back, 2 witnesses written, 3 parked) and its data.
 * resume=2, the PM core's way back (note 77 §11): 4 out of .enter, 5 syscore_resume (ours is
 * registered last, so it runs last), 6 .wake (IRQs on, secondaries brought up; data: CPUs online),
 * 7 resume_early (the noirq phase done), 8 resume (the early phase done), 9 PM_POST_SUSPEND
 * (devices, console, tasks back), 10 a work item 5 s after 9.
 */
#define SEQ_RESUME_MAGIC	(0x525355ULL << 40)
#define PMU_BOOT_STAGE_RUNNING	0x30

/*
 * The secondaries' turns. The parked CPUs answer the stop together; macOS's write their stop
 * requests one at a time in CPU order, and take their last WFI the same way.
 */
static atomic_t aseq_turn = ATOMIC_INIT(-1);

static void aseq_turn_wait(unsigned int cpu)
{
	int us;

	for (us = 0; us < SEQ_TURN_US; us++) {
		if (atomic_read(&aseq_turn) >= (int)cpu)
			return;
		udelay(1);
	}
}

static void aseq_turn_pass(unsigned int cpu)
{
	unsigned int next = cpumask_next(cpu, cpu_present_mask);

	atomic_set(&aseq_turn, next < nr_cpu_ids ? next : INT_MAX);
}

static void aseq_turn_start(void)
{
	unsigned int first = cpumask_next(0, cpu_present_mask);

	atomic_set(&aseq_turn, first < nr_cpu_ids ? first : INT_MAX);
}

/* The last present CPU of its cluster in CPU order; the boot CPU's cluster ends with it. */
static bool aseq_cpu_last_of_cluster(unsigned int cpu)
{
	u64 mpidr = cpu_logical_map(cpu);
	unsigned int other;

	for_each_present_cpu(other) {
		u64 m = cpu_logical_map(other);

		if (MPIDR_AFFINITY_LEVEL(m, 2) != MPIDR_AFFINITY_LEVEL(mpidr, 2) ||
		    MPIDR_AFFINITY_LEVEL(m, 1) != MPIDR_AFFINITY_LEVEL(mpidr, 1))
			continue;
		if (other == 0 || other > cpu)
			return false;
	}

	return true;
}

/* A secondary in cpu0's cluster (E): its last core is cpu0, so it never counts as last. */
static bool aseq_cpu_in_boot_cluster(unsigned int cpu)
{
	u64 m = cpu_logical_map(cpu), b = cpu_logical_map(0);

	return MPIDR_AFFINITY_LEVEL(m, 2) == MPIDR_AFFINITY_LEVEL(b, 2) &&
	       MPIDR_AFFINITY_LEVEL(m, 1) == MPIDR_AFFINITY_LEVEL(b, 1);
}

/* CPU_START's bit: four per cluster, cluster in affinity 1 (P cores are 0.1.n, 0.2.n). */
static u32 aseq_cpu_start_bit(u64 mpidr)
{
	return BIT(4 * MPIDR_AFFINITY_LEVEL(mpidr, 1) + MPIDR_AFFINITY_LEVEL(mpidr, 0));
}

/*
 * macOS's arm64_prepare_for_sleep(deep): ACC_OVRD's deep fields from the last core of a
 * cluster only (from any other it takes the running siblings down), then CYC_OVRD's power-gate
 * in IRQ/FIQ mode 0. No SIQ_CFG and no mode 2: those are runtime parking.
 */
/* macOS's values at its edge (pd438, cpu0 and cpu4 alike, PMCR0 aside), each behind its group */
static void aseq_core_regs(void)
{
	u64 g = READ_ONCE(aseq_core_groups);

	if (g & SEQ_G_HID5)
		write_sysreg_s((read_sysreg_s(SYS_IMP_APL_HID5) & ~HID5_UNK_19_18) | HID5_UNK19,
			       SYS_IMP_APL_HID5);
	if (g & SEQ_G_IPICR)
		write_sysreg_s(IPI_CR_MACOS, SYS_IMP_APL_IPI_CR_EL1);
	if (g & SEQ_G_SIQCFG)
		write_sysreg_s(0, SYS_IMP_APL_SIQ_CFG_EL1);
	if (g & SEQ_G_PMUCFG) {
		/* PMCR0 stays edge_timer's; the uncore counters' interrupt mode stays off (0x7ff) */
		write_sysreg_s(0xf0f00, SYS_IMP_APL_PMCR1_EL1);
		write_sysreg_s(0xa3a2, SYS_IMP_APL_PMESR0_EL1);
		write_sysreg_s(0xde68676665111002ULL, SYS_IMP_APL_UPMESR0_EL1);
		write_sysreg_s(0xdbdcdd, SYS_IMP_APL_UPMESR1_EL1);
		write_sysreg_s(~0ULL, SYS_IMP_APL_UPMECM0_EL1);
		write_sysreg_s(~0ULL, SYS_IMP_APL_UPMECM1_EL1);
		write_sysreg_s(0xffffffffffffULL, SYS_IMP_APL_UPMECM2_EL1);
		write_sysreg_s(0x7ff, SYS_IMP_APL_UPMCR0_EL1);
	}
	isb();
}

static void aseq_boot_crumb(void);

static void aseq_deep_request(bool last_of_cluster, bool boot)
{
	u64 v;

	aseq_core_regs();

	write_sysreg(ARCH_TIMER_CTRL_IT_MASK, cntp_ctl_el0);
	if (boot && edge_timer) {
		/* Due now, enabled, unmasked: it fires with DAIF masked, as macOS's does */
		write_sysreg(__arch_counter_get_cntvct(), cntv_cval_el0);
		write_sysreg(ARCH_TIMER_CTRL_ENABLE, cntv_ctl_el0);
		write_sysreg_s(PMCR0_MACOS_EDGE, SYS_IMP_APL_PMCR0_EL1);
		isb();
	} else {
		write_sysreg(ARCH_TIMER_CTRL_IT_MASK, cntv_ctl_el0);
	}
	aseq_quench(boot);

	if (last_of_cluster) {
		v = read_sysreg_s(SYS_IMP_APL_ACC_OVRD);
		v &= ~(ACC_OVRD_PWR_DN_SRM | ACC_OVRD_DIS_L2_FLUSH | ACC_OVRD_TRAIN_DOWN_LINK |
		       ACC_OVRD_POWER_DOWN_CPM);
		v |= FIELD_PREP(ACC_OVRD_PWR_DN_SRM, 3) | FIELD_PREP(ACC_OVRD_DIS_L2_FLUSH, 2) |
		     FIELD_PREP(ACC_OVRD_TRAIN_DOWN_LINK, 3) |
		     FIELD_PREP(ACC_OVRD_POWER_DOWN_CPM, 3) | ACC_OVRD_DISABLE_PIO_ON_WFI |
		     ACC_OVRD_DEEP_SLEEP;
		write_sysreg_s(v, SYS_IMP_APL_ACC_OVRD);
	}

	v = read_sysreg_s(SYS_IMP_APL_CYC_OVRD);
	v &= ~(CYC_OVRD_FIQ_MODE_MASK | CYC_OVRD_IRQ_MODE_MASK);
	if (boot && (READ_ONCE(hybrid) & ASEQ_HYBRID_NATIVE_EDGE_CNTPCT) && apple_sleep_seq &&
	    apple_sleep_seq->mbox) {
		/* The very last thing before the WFI: the boot object's re-gate window starts here */
		struct aura_s2r_mailbox *mb = apple_sleep_seq->mbox;

		aseq_edge_cntpct = __arch_counter_get_cntpct();
		WRITE_ONCE(mb->edge_cntpct, aseq_edge_cntpct);
		dcache_clean_poc((unsigned long)mb, (unsigned long)(mb + 1));
		dsb(sy);
	}
	if (boot)
		aseq_boot_crumb();
	write_sysreg_s(v | CYC_OVRD_DEEP, SYS_IMP_APL_CYC_OVRD);
}

static void __noreturn aseq_last_wfi(void)
{
	while (true) {
		dsb(sy);
		isb();
		wfi();
		write_sysreg_s(IPI_SR_PENDING, SYS_IMP_APL_IPI_SR_EL1);
		/* A bounce through the WFI (a latched timer, IPI or PMI): quiet it again, per the quench bits */
		aseq_quench(raw_smp_processor_id() == 0);
	}
}

static void aseq_cpu_stop(u64 mpidr)
{
	struct apple_sleep_seq *s = apple_sleep_seq;
	int cpu = get_logical_index(mpidr);

	if (cpu > 0)
		aseq_turn_wait(cpu);
	writel(aseq_cpu_start_bit(mpidr),
	       s->base[s->soc->cpu_start_blk] + s->soc->cpu_start_off + CPU_START_STOP);
	dsb(sy);
	if (cpu > 0) {
		atomic_inc(&aseq_stopped);
		aseq_turn_pass(cpu);
	}
}

static void aseq_cpu_off(u64 mpidr)
{
	int cpu = get_logical_index(mpidr);
	bool last = cpu > 0 && aseq_cpu_last_of_cluster(cpu);
	/*
	 * EDEEP: macOS's cpu1-3 write the E cluster's deep ACC_OVRD before EACC <- 0 (the HV
	 * records it from them in 31 of 35 macOS runs, from Linux's in 0 of 65), and cpu0
	 * keeps running. Not the turn's last: only its ACC_OVRD changes.
	 */
	bool edeep = cpu > 0 && (READ_ONCE(aseq_core_groups) & SEQ_G_EDEEP) &&
		     aseq_cpu_in_boot_cluster(cpu);

	/* PACCALL: macOS's P cores all write the deep ACC_OVRD, the HV records it from each (pd616) */
	bool paccall = cpu > 0 && (READ_ONCE(aseq_core_groups) & SEQ_G_PACCALL) &&
		       !aseq_cpu_in_boot_cluster(cpu);

	if (cpu > 0)
		aseq_turn_wait(cpu);
	/* Its siblings passed the turn just before their own last writes. */
	if (last)
		udelay(100);
	if (cpu > 0)
		aseq_turn_pass(cpu);
	aseq_deep_request(last || edeep || paccall, false);
	atomic_inc(&aseq_down);
	aseq_last_wfi();
}

/*
 * Back after a wake (note 85). Under the bench HV the cluster word's write is the HV's cold start
 * (hv_s2a_cpustart_hook): the core resets into the guest m1n1, whose spin table still sends it to
 * secondary_holding_pen. A P cluster has to be on first: macOS's wake writes its cluster-ctl word
 * 0x2f before the cluster's first core (note 25 phase 6), then each core's CPU_START +4 and its
 * cluster word, in CPU order. Bench switches: hybrid bit 16 cpu0's cluster (E), bit 17 the P cores.
 */
#define ASEQ_HYBRID_CPUON_E		BIT(16)
#define ASEQ_HYBRID_CPUON_P		BIT(17)
#define ASEQ_CLUSTER_CTL		0x8000	/* T6020_CLUSTER_CTL, one word per domain, P cluster n at 4n */
#define ASEQ_CLUSTER_CTL_ON		0xf
#define ASEQ_CLUSTER_CTL_PWRUP		BIT(5)	/* the power-up event (PACCn_PWRUP), W1C */
#define ASEQ_CPU_START_ALL		0x4
#define ASEQ_CPU_START_CLUSTER(cl)	(0x8 + 4 * (cl))

static void aseq_cluster_up(unsigned int cl)
{
	struct apple_sleep_seq *s = apple_sleep_seq;
	void __iomem *ctl = s->base[s->soc->cpu_start_blk] + ASEQ_CLUSTER_CTL + 4 * cl;
	u32 v0 = readl(ctl), v;
	ktime_t t0;
	int ret;

	if ((v0 & 0xf) == ASEQ_CLUSTER_CTL_ON) {
		pr_info("apple-sleep: cpu-on: cluster %u ctl %#x, already on\n", cl, v0);
		return;
	}

	t0 = ktime_get();
	/* macOS's one write: on, and a stale event acked */
	writel(ASEQ_CLUSTER_CTL_ON | ASEQ_CLUSTER_CTL_PWRUP, ctl);
	ret = readl_poll_timeout_atomic(ctl, v, v & ASEQ_CLUSTER_CTL_PWRUP, 1, 5000);
	if (!ret)
		writel(v | ASEQ_CLUSTER_CTL_PWRUP, ctl);
	pr_info("apple-sleep: cpu-on: cluster %u ctl %#x -> %#x, power-up event %s in %lld us, then %#x\n",
		cl, v0, v, ret ? "missing" : "seen", ktime_us_delta(ktime_get(), t0), readl(ctl));
}

static int aseq_cpu_on(u64 mpidr)
{
	struct apple_sleep_seq *s = apple_sleep_seq;
	void __iomem *cs = s->base[s->soc->cpu_start_blk] + s->soc->cpu_start_off;
	int cpu = get_logical_index(mpidr);
	unsigned int cl = MPIDR_AFFINITY_LEVEL(mpidr, 1), core = MPIDR_AFFINITY_LEVEL(mpidr, 0);
	bool boot_cl = cpu > 0 && aseq_cpu_in_boot_cluster(cpu);

	if (cpu <= 0 || !(READ_ONCE(hybrid) & (boot_cl ? ASEQ_HYBRID_CPUON_E : ASEQ_HYBRID_CPUON_P)))
		return -EOPNOTSUPP;

	if (!boot_cl)
		aseq_cluster_up(cl);

	writel(aseq_cpu_start_bit(mpidr), cs + ASEQ_CPU_START_ALL);
	writel(BIT(core), cs + ASEQ_CPU_START_CLUSTER(cl));
	dsb(sy);

	return 0;
}

/*
 * Hybrid bit 18: after a wake, before RSU|10, every online CPU runs a fixed dependent multiply chain
 * at once (the load), then sleeps 20 ms (its own timer and a remote wake-up). One line per CPU:
 * the chain's time (cores of a kind should match each other and cpu0's E cores), cpufreq's
 * current kHz, the interrupts it took during the sleep, and CYC_OVRD/ACC_OVRD as it runs.
 */
#define ASEQ_HYBRID_CPUCHECK		BIT(18)
#define ASEQ_CHECK_CHAIN		(1UL << 26)	/* ~60-100 ms of madd latency */

/*
 * Hybrid bit 19: the same check at PM_SUSPEND_PREPARE, before the freeze, as the baseline the
 * wake's check is read against (it starts the entry ~0.3 s later). Both checks also print each CPU
 * cluster's DVFS registers: CMD and STATUS (what apple-soc-cpufreq reads), and PLL_FACTOR.
 */
#define ASEQ_HYBRID_CPUCHECK_PRE	BIT(19)
#define ASEQ_DVFS_CMD			0x20
#define ASEQ_DVFS_CMD_PS1		GENMASK_ULL(4, 0)
#define ASEQ_DVFS_STATUS		0x50
#define ASEQ_DVFS_STATUS_CUR		GENMASK_ULL(9, 5)	/* the t8112 layout, t6020's too */
#define ASEQ_DVFS_STATUS_TGT		GENMASK_ULL(4, 0)
#define ASEQ_DVFS_PLL_FACTOR		0xc8
#define ASEQ_DVFS_PLL_MULT		GENMASK_ULL(31, 16)
#define ASEQ_DVFS_PLL_DIV		GENMASK_ULL(15, 0)

/* the opp-hz of opp-level @ps in the OPP table of the CPUs whose performance domain is @np */
static u64 aseq_dvfs_opp_hz(struct device_node *np, u32 ps)
{
	struct device_node *opp_np = NULL, *child;
	unsigned int cpu;
	u64 hz = 0;

	for_each_possible_cpu(cpu) {
		struct device_node *cpu_np = of_get_cpu_node(cpu, NULL);
		struct device_node *dom = cpu_np ? of_parse_phandle(cpu_np, "performance-domains", 0) : NULL;

		if (dom == np)
			opp_np = of_parse_phandle(cpu_np, "operating-points-v2", 0);
		of_node_put(dom);
		of_node_put(cpu_np);
		if (opp_np)
			break;
	}
	if (!opp_np)
		return 0;
	for_each_available_child_of_node(opp_np, child) {
		u32 level;

		if (!of_property_read_u32(child, "opp-level", &level) && level == ps &&
		    !of_property_read_u64(child, "opp-hz", &hz)) {
			of_node_put(child);
			break;
		}
	}
	of_node_put(opp_np);
	return hz;
}

static void aseq_dvfs_dump(const char *when)
{
	struct device_node *np;

	for_each_compatible_node(np, NULL, "apple,t6020-cluster-cpufreq") {
		void __iomem *base = of_iomap(np, 0);
		u64 cmd, st, pll, mult, div;

		if (!base) {
			pr_err("apple-sleep: cpu-check %s: dvfs %pOFn: no mapping\n", when, np);
			continue;
		}
		cmd = readq_relaxed(base + ASEQ_DVFS_CMD);
		st = readl_relaxed(base + ASEQ_DVFS_STATUS);
		pll = readl_relaxed(base + ASEQ_DVFS_PLL_FACTOR);
		iounmap(base);
		mult = FIELD_GET(ASEQ_DVFS_PLL_MULT, pll);
		div = FIELD_GET(ASEQ_DVFS_PLL_DIV, pll);
		pr_info("apple-sleep: cpu-check %s: dvfs %pOF: cmd %#llx (ps %llu, %llu MHz) status %#llx (cur %llu, %llu MHz; tgt %llu) pll_factor %#llx (%llu MHz)\n",
			when, np, cmd, FIELD_GET(ASEQ_DVFS_CMD_PS1, cmd),
			aseq_dvfs_opp_hz(np, FIELD_GET(ASEQ_DVFS_CMD_PS1, cmd)) / 1000000, st,
			FIELD_GET(ASEQ_DVFS_STATUS_CUR, st),
			aseq_dvfs_opp_hz(np, FIELD_GET(ASEQ_DVFS_STATUS_CUR, st)) / 1000000,
			FIELD_GET(ASEQ_DVFS_STATUS_TGT, st), pll, 12 * mult / (div + 1));
	}
}

struct aseq_cpu_check {
	struct work_struct work;
	struct completion done;
	bool queued;
	int ran_on;
	u64 chain_us, irqs, cyc, acc;
};

static void aseq_cpu_check_fn(struct work_struct *work)
{
	struct aseq_cpu_check *c = container_of(work, struct aseq_cpu_check, work);
	unsigned int cpu = smp_processor_id();
	u64 x = 1, n, irqs0;
	ktime_t t0;

	c->ran_on = cpu;
	t0 = ktime_get();
	for (n = 0; n < ASEQ_CHECK_CHAIN; n++)
		asm volatile("madd %0, %0, %0, %1" : "+r"(x) : "r"(n));
	c->chain_us = ktime_us_delta(ktime_get(), t0);
	c->cyc = read_sysreg_s(SYS_IMP_APL_CYC_OVRD);
	c->acc = read_sysreg_s(SYS_IMP_APL_ACC_OVRD);
	irqs0 = kstat_cpu_irqs_sum(cpu);
	msleep(20);
	c->irqs = kstat_cpu_irqs_sum(cpu) - irqs0;
	complete(&c->done);
}

/*
 * Hybrid bit 20 (ENTRY_PSTATE): cpufreq_suspend() puts every cluster at its lowest OPP
 * (E 912, P 702 MHz), so the entry would run on cpu0 at 912 MHz. Put each policy's suspend
 * frequency at m1n1's t6020 default p-state instead (src/cpufreq.c: E 5, P 6), so the entry runs
 * at the clocks of every bench run before Linux DVFS (lx-entry, note 85 §7). Nothing without
 * a cpufreq driver.
 */
#define ASEQ_HYBRID_ENTRY_PSTATE	BIT(20)
#define ASEQ_ENTRY_PSTATE_E		5
#define ASEQ_ENTRY_PSTATE_P		6

static void aseq_entry_pstate(void)
{
	struct device_node *np;

	for_each_compatible_node(np, NULL, "apple,t6020-cluster-cpufreq") {
		struct cpufreq_policy *policy = NULL;
		unsigned int cpu, old;
		u32 level = 0;
		u64 hz;

		for_each_online_cpu(cpu) {
			struct device_node *cpu_np = of_get_cpu_node(cpu, NULL);
			struct device_node *dom = cpu_np ? of_parse_phandle(cpu_np, "performance-domains", 0) : NULL;
			bool match = dom == np;

			of_node_put(dom);
			of_node_put(cpu_np);
			if (match) {
				policy = cpufreq_cpu_get(cpu);
				level = aseq_cpu_in_boot_cluster(cpu) ? ASEQ_ENTRY_PSTATE_E : ASEQ_ENTRY_PSTATE_P;
				break;
			}
		}
		if (!policy)
			continue;
		hz = aseq_dvfs_opp_hz(np, level);
		old = policy->suspend_freq;
		if (hz)
			policy->suspend_freq = hz / 1000;
		pr_info("apple-sleep: entry p-state: policy cpu%u (%pOF) suspend_freq %u -> %u kHz (level %u)\n",
			policy->cpu, np, old, policy->suspend_freq, level);
		cpufreq_cpu_put(policy);
	}
}

static void aseq_cpu_check(const char *when)
{
	static struct aseq_cpu_check checks[NR_CPUS];
	unsigned int cpu, answered = 0;
	unsigned long left = 3 * HZ;

	aseq_dvfs_dump(when);

	for_each_online_cpu(cpu) {
		struct aseq_cpu_check *c = &checks[cpu];

		/* one still queued or running from a wake whose check timed out: leave it be */
		if (c->work.func && work_busy(&c->work)) {
			c->queued = false;
			pr_err("apple-sleep: cpu-check %s: cpu%u still has an earlier check queued\n", when, cpu);
			continue;
		}
		memset(c, 0, sizeof(*c));
		c->ran_on = -1;
		INIT_WORK(&c->work, aseq_cpu_check_fn);
		init_completion(&c->done);
		c->queued = true;
		queue_work_on(cpu, system_highpri_wq, &c->work);
	}
	for_each_online_cpu(cpu) {
		struct aseq_cpu_check *c = &checks[cpu];
		unsigned long t;

		if (!c->queued)
			continue;
		/* the wait consumes the completion: its return value is the only answer */
		t = wait_for_completion_timeout(&c->done, left ?: 1);
		if (!t) {
			left = 0;
			pr_err("apple-sleep: cpu-check %s: cpu%u did not run its check in 3 s\n", when, cpu);
			continue;
		}
		left = t;
		answered++;
		pr_info("apple-sleep: cpu-check %s: cpu%u mpidr %#llx ran on %d, chain %llu us, %u kHz, irqs +%llu in 20 ms, cyc_ovrd %#llx acc_ovrd %#llx\n",
			when, cpu, cpu_logical_map(cpu), c->ran_on, c->chain_us, cpufreq_quick_get(cpu),
			c->irqs, c->cyc, c->acc);
	}
	pr_info("apple-sleep: cpu-check %s: %u online of %u present, %u answered\n",
		when, num_online_cpus(), num_present_cpus(), answered);
}

static const struct spin_table_power_ops aseq_cpu_power_ops = {
	.cpu_stop = aseq_cpu_stop,
	.cpu_off = aseq_cpu_off,
	.cpu_on = aseq_cpu_on,
};

static u64 aseq_groups(void)
{
	u64 g = READ_ONCE(seq_groups);

	if (g == SEQ_G_UNSET)
		g = dry_run ? SEQ_G_DEFAULT_DRY : SEQ_G_DEFAULT_FULL;
	if (dry_run)
		g &= ~SEQ_G_REAL;

	return g;
}

static bool aseq_op_runs(const struct apple_sleep_seq *s, const struct apple_sleep_op *op)
{
	/* An external DCP a driver has bound is that driver's: neither its ASC stop nor its words */
	if (s->dispext_bound && s->dispext_rows && op >= s->soc->entry &&
	    op < s->soc->entry + s->soc->nentry && test_bit(op - s->soc->entry, s->dispext_rows) &&
	    (s->dispext_bound & BIT(test_bit(op - s->soc->entry, s->dispext1_rows))))
		return false;
	/* dispext_off ran these rows already, at boot or .begin */
	if (s->dispext_done && op >= s->soc->entry && op < s->soc->entry + s->soc->nentry &&
	    test_bit(op - s->soc->entry, s->dispext_rows))
		return false;
	if (op->kind == SEQ_DELAY && !delays)
		return false;
	/* CLACK waits for the ack instead of the cluster-ctl's blind delays; it has no write without CLCTL */
	if (op->kind == SEQ_DELAY && op->group == SEQ_G_CLCTL && (s->groups & SEQ_G_CLACK))
		return false;
	if (op->kind == SEQ_CLACK32 && !(s->groups & SEQ_G_CLCTL))
		return false;
	if (op->group == SEQ_G_AFRWAIT && !(s->groups & SEQ_G_AFR))
		return false;
	/* SPMIIDLE reads the RTC before its wait, so no SPMI traffic sits between C14 and commit 1 */
	if (op->kind == SEQ_PMU_RTC_NOW && op->group == SEQ_G_SPMIIDLE && !(s->groups & SEQ_G_PMU))
		return false;
	if (op->kind == SEQ_PMU_RTC_NOW && op->group == SEQ_G_PMU && (s->groups & SEQ_G_SPMIIDLE))
		return false;

	if (op->kind == SEQ_PS_EDGE || op->kind == SEQ_EDGE_SET32 || op->kind == SEQ_EDGE_W32)
		return edge_on & BIT(SEQ_PS_EDGE_BIT(op->val));
	return op->group & s->groups;
}

static bool aseq_op_pmu(const struct apple_sleep_op *op)
{
	return op->kind >= SEQ_PMU_W8 && op->kind <= SEQ_PMU_ALARM;
}

/*
 * The PMU's SPMI bus, polled, interrupts off: macOS's own sequence (pd145, pd158), as aurora's
 * sleep_pmu_write does it on T8140. The reply's notify is masked, then acknowledged, so nothing
 * is left raised for the controller's driver.
 */
#define SPMI_STATUS		0x00
#define SPMI_STATUS_RX_EMPTY	BIT(24)
#define SPMI_CMD		0x04
#define SPMI_REPLY		0x08
#define SPMI_NOTIFY_ENABLE	0x40
#define SPMI_NOTIFY_REPLY	BIT(0)
#define SPMI_NOTIFY_ACK		0x80
#define SPMI_CMD_ACTIVE		BIT(15)
#define SPMI_REPLY_ACK		BIT(15)
#define SPMI_REPLY_SID		GENMASK(14, 8)
#define SPMI_REPLY_OP		GENMASK(7, 0)
#define SPMI_REPLY_PARITY	GENMASK(31, 16)
#define SPMI_DRAIN_MAX		16
#define SPMI_OP_EXT_WRITEL	0x30
#define SPMI_OP_EXT_READL	0x38
#define SPMI_POLL_US		20000

static int aseq_spmi_rx(void __iomem *b, u32 *word)
{
	u32 status;
	int ret;

	ret = readl_poll_timeout_atomic(b + SPMI_STATUS, status, !(status & SPMI_STATUS_RX_EMPTY),
					1, SPMI_POLL_US);
	if (!ret)
		*word = readl(b + SPMI_REPLY);

	return ret;
}

/* One ext-write-long (nwr bytes, 1..8) or ext-read-long (nrd bytes, 1..8) */
static int aseq_spmi(struct apple_sleep_seq *s, u16 reg, const u8 *wr, unsigned int nwr,
		     u8 *rd, unsigned int nrd)
{
	void __iomem *b = s->base[s->soc->pmu_blk];
	u8 op = nwr ? SPMI_OP_EXT_WRITEL | (nwr - 1) : SPMI_OP_EXT_READL | (nrd - 1);
	u32 enable, reply, word;
	unsigned int i;
	int ret;

	enable = readl(b + SPMI_NOTIFY_ENABLE);
	writel(enable & ~SPMI_NOTIFY_REPLY, b + SPMI_NOTIFY_ENABLE);
	/* A late reply left by the controller's own driver must not pass for this one's */
	for (i = 0; i < SPMI_DRAIN_MAX && !(readl(b + SPMI_STATUS) & SPMI_STATUS_RX_EMPTY); i++)
		readl(b + SPMI_REPLY);
	writel((u32)reg << 16 | SPMI_CMD_ACTIVE | (u32)s->soc->pmu_sid << 8 | op, b + SPMI_CMD);
	for (i = 0; i < nwr; i += 4) {
		word = 0;
		memcpy(&word, wr + i, min(4U, nwr - i));
		writel(word, b + SPMI_CMD);
	}

	ret = aseq_spmi_rx(b, &reply);
	if (!ret && (FIELD_GET(SPMI_REPLY_OP, reply) != op ||
		     FIELD_GET(SPMI_REPLY_SID, reply) != s->soc->pmu_sid))
		ret = -EPROTO;
	for (i = 0; !ret && i < nrd; i += 4) {
		ret = aseq_spmi_rx(b, &word);
		memcpy(rd + i, &word, min(4U, nrd - i));
	}
	if (!ret && !nrd && !(reply & SPMI_REPLY_ACK))
		ret = -EIO;
	/* One parity bit per data frame read, as the controller's driver checks it */
	if (!ret && nrd && (~FIELD_GET(SPMI_REPLY_PARITY, reply) & GENMASK(nrd - 1, 0)))
		ret = -EIO;
	if (!ret && !(readl(b + SPMI_STATUS) & SPMI_STATUS_RX_EMPTY))
		ret = -EIO;

	writel(1, b + SPMI_NOTIFY_ACK);
	writel(enable, b + SPMI_NOTIFY_ENABLE);

	return ret;
}

static void aseq_pmu_run(struct apple_sleep_seq *s, const struct apple_sleep_op *op,
			 unsigned int step)
{
	u8 buf[8] = {};
	int ret = 0;

	switch (op->kind) {
	case SEQ_PMU_W8:
		buf[0] = op->val;
		ret = aseq_spmi(s, op->off, buf, 1, NULL, 0);
		break;
	case SEQ_PMU_R:
		ret = aseq_spmi(s, op->off, NULL, 0, buf, op->val);
		break;
	case SEQ_PMU_RTC_NOW:
		ret = aseq_spmi(s, op->off, NULL, 0, buf, 6);
		s->rtc_now = get_unaligned_le64(buf) & GENMASK_ULL(47, 0);
		break;
	case SEQ_PMU_ALARM:
		/* 48 bits with 16 fractional, the alarm in whole seconds (pd158: now 0x2ec55 s, 0x2ec91) */
		s->alarm = (s->rtc_now >> 16) + READ_ONCE(alarm_s);
		put_unaligned_le32(s->alarm, buf);
		ret = aseq_spmi(s, op->off, buf, 4, NULL, 0);
		break;
	}
	if (ret && !s->pmu_ret) {
		s->pmu_ret = ret;
		s->pmu_ret_step = step;
	}
}

/* Whether the RTC as read here is .begin's plus the time since, within the slack */
static bool aseq_rtc_sane(struct apple_sleep_seq *s)
{
	u64 now_s = s->rtc_now >> 16, want;

	if (!s->rtc_now || !s->rtc_begin_s)
		return false;
	want = s->rtc_begin_s + div_u64(__arch_counter_get_cntvct() - s->cnt_begin,
					arch_timer_get_cntfrq());

	return now_s + SEQ_RTC_SLACK_S >= want && now_s <= want + SEQ_RTC_SLACK_S;
}

/* The alarm as the PMU has it now, against what was written, and armed */
static bool aseq_alarm_sane(struct apple_sleep_seq *s)
{
	u8 buf[8] = {}, ctrl = 0;

	if (aseq_spmi(s, PMU_RTC_ALARM, NULL, 0, buf, 4) ||
	    aseq_spmi(s, PMU_RTC_ALARM_CTRL, NULL, 0, &ctrl, 1))
		return false;

	return get_unaligned_le32(buf) == s->alarm && ctrl == PMU_RTC_ALARM_ARM;
}

/* 0, or the checks that failed: then nothing irreversible follows */
static u32 aseq_gate(struct apple_sleep_seq *s, u32 checks)
{
	u32 failed = 0;

	if ((checks & SEQ_GATE_PMU) && s->pmu_ret)
		failed |= SEQ_GATE_PMU;
	if ((checks & SEQ_GATE_RTC) && !aseq_rtc_sane(s))
		failed |= SEQ_GATE_RTC;
	/* note 63: edge_on bit 18 drops the read-back, so 0x1401 <- 0x41 is the last SPMI transaction, as macOS */
	if ((checks & SEQ_GATE_ALARM) && !(edge_on & BIT(18)) && !aseq_alarm_sane(s))
		failed |= SEQ_GATE_ALARM;

	return failed;
}

/* An MMIO word the step writes, saved before it does */
static bool aseq_op_writes(const struct apple_sleep_op *op)
{
	return op->kind <= SEQ_PS_NO_AUTO || op->kind == SEQ_DEADLINE;
}

/* Whether a writing step reads its word first, for the plan's "now" and saved[] */
static bool aseq_op_reads(const struct apple_sleep_seq *s, const struct apple_sleep_op *op)
{
	if (!aseq_op_writes(op))
		return false;
	/* The PS steps compute their value from the word */
	if (op->kind != SEQ_W32 && op->kind != SEQ_W64)
		return true;
	/* The commit is a trigger, not state */
	if (op->blk == s->soc->commit_blk)
		return false;

	return read_cluster || !(s->soc->noread_blocks & BIT(op->blk));
}

static bool aseq_op_is64(const struct apple_sleep_op *op)
{
	return op->kind == SEQ_W64 || op->kind == SEQ_SET64;
}

static u64 aseq_read(void __iomem *reg, const struct apple_sleep_op *op)
{
	return aseq_op_is64(op) ? readq(reg) : readl(reg);
}

static u32 aseq_deadline(u32 secs)
{
	return div_u64(__arch_counter_get_cntvct(), arch_timer_get_cntfrq()) + secs;
}

static int aseq_ps_wait(void __iomem *reg, u32 actual)
{
	u32 v;

	return readl_poll_timeout_atomic(reg, v, FIELD_GET(PS_ACTUAL, v) == actual, 1, PS_POLL_US);
}

static int aseq_clack_wait(void __iomem *reg, u32 *v)
{
	return readl_poll_timeout_atomic(reg, *v, !(*v & SEQ_CLACK_BIT), 1, SEQ_CLACK_US);
}

/* Through the device's driver, if it registered a stop (sleep.c's registry); 0 if none did */
static int aseq_coproc_stop(struct apple_sleep_seq *s, unsigned int i)
{
	if (i >= ARRAY_SIZE(s->coproc) || !s->coproc[i])
		return -ENODEV;

	return apple_sleep_coproc_stop(s->coproc[i]);
}

/* One step of the entry, after its word is saved. Interrupts off, no printing. */
/*
 * Hybrid bit 28 (note 86, cycle 2 of a boot cuts 0 of 6): aurora's T6040 second sleep of a boot "waited and the
 * chip reset" because the wake had armed ANS's fabric bridge (+0x104/+0x108 bit 0, 05312c21) and left BUSY latched
 * on PS words (apple_sleep_ps_unlatch). Here, right before commit 1: every PS word with BUSY (bit 11) and target and
 * actual 0 is unlatched aurora's way (off | bit 12, wait BUSY clear, off); ANS's bridge (ADT pmgr reg[48+15],
 * 0x349000000) is read while ANS is on, the first entry's words kept, and on a later entry bit 0 of +0x104/+0x108
 * is put back to the first entry's. Crumbs (PMU boot_stage, after the table's 0x50): 0x5d a PS word still BUSY,
 * 0x5e the bridge's bit 0 differed, 0x5f both, 0x5b none of them (the row ran, the ANS bridge read), 0x5a none and the bridge not read.
 */
#define ASEQ_HYBRID_ENTRY2	BIT(28)
/*
 * m2pro-7.3.4 (b5w): bit 28 is a witness only: its crumbs are the only write (PMU boot_stage). native14's
 * actions (the unlatch, the bridge's bit 0 put back) are compiled out: native14 found nothing to act on (0x5b,
 * 2 of 2), and no hybrid bit is free for them here. The crumb values keep native14's meaning, read before any
 * action: 0x5d a word stays BUSY-latched, 0x5e the bridge's bit 0 differs from entry 1, 0x5f both.
 */
#define ASEQ_HYBRID_ENTRY2_ACT	0U
#define ASEQ_PS_BUSY		BIT(11)
#define ASEQ_PS_UNLATCH		BIT(12)
#define ASEQ_PS_DEV_DISABLE	BIT(10)
#define ASEQ_ANS_BRIDGE_PA	0x349000000ULL
#define ASEQ_BRIDGE_104		0x104
#define ASEQ_BRIDGE_108		0x108

/*
 * Hybrid bit 31 (native17/18): the state witnesses as boot_stage values only, no other PMU cell (note
 * native16-pmu-cells.md). At each entry (entry2's row) the PS words are compared with the first entry's snapshot
 * (TARGET, ACTUAL, BUSY). With hybrid bit 29 the post-commit-2 crumb (0x63's spot) names the first differing word
 * (index = position in the DT's pmgr-pwrstate nodes, notes/sleep/ps-index-j416s.txt): 0x73 none, 0x81 + (idx - 32)
 * for idx 32..47 (0x81..0x90), 0x91 any other. With bits 29 and 30 the crumb before cpu0's CYC_OVRD write (0x64's
 * spot) names what differs in that word instead: 0x91 + (mask - 1), mask = 1 TARGET, 2 ACTUAL, 4 BUSY ORed
 * (0x91..0x97), 0x73 none; the first word is the one the other arm names. With bit 30 alone that crumb is 0x66 + N,
 * N = CPUs stopped by the table but not confirmed down (0..11), or 0x72 if it stopped fewer than nr_cpu_ids - 1.
 */
#define ASEQ_HYBRID_STATE_DUMP	BIT(31)
static unsigned int aseq_entries;
static u32 aseq_ans_first[3];
static void __iomem *aseq_ans_bridge;
static u32 *aseq_ps_first;
static u8 aseq_ps_crumb = 0x73;
static u8 aseq_ps_field = 0x73;

static void aseq_dump_map(struct apple_sleep_seq *s)
{
	if (!(READ_ONCE(hybrid) & ASEQ_HYBRID_STATE_DUMP))
		return;
	if (!aseq_ps_first)
		aseq_ps_first = kcalloc(s->nps, sizeof(u32), GFP_KERNEL);
}

static void aseq_dump_ps(struct apple_sleep_seq *s)
{
	unsigned int i, first = UINT_MAX, fields = 0;
	const u32 mask = PS_TARGET | PS_ACTUAL | ASEQ_PS_BUSY;

	if (!aseq_ps_first)
		return;
	for (i = 0; i < s->nps; i++) {
		u32 v = readl(s->ps[i].reg) & mask;

		if (!aseq_entries)
			aseq_ps_first[i] = v;
		else if (v != aseq_ps_first[i] && first == UINT_MAX) {
			u32 x = v ^ aseq_ps_first[i];

			first = i;
			fields = (x & PS_TARGET ? 1 : 0) | (x & PS_ACTUAL ? 2 : 0) | (x & ASEQ_PS_BUSY ? 4 : 0);
		}
	}
	if (first == UINT_MAX)
		aseq_ps_crumb = aseq_ps_field = 0x73;
	else {
		aseq_ps_crumb = first >= 32 && first <= 47 ? 0x81 + (first - 32) : 0x91;
		aseq_ps_field = 0x91 + (fields - 1);
	}
	pr_emerg("apple-sleep: entry2: entry %u: first PS word differing from entry 1: %d, fields %#x (crumbs %#x, %#x)\n",
		 aseq_entries + 1, first == UINT_MAX ? -1 : (int)first, fields, aseq_ps_crumb, aseq_ps_field);
}

/*
 * Entry-step crumbs (PMU boot_stage, one SPMI write each) with hybrid bit 28; 0x60 after the AIC mask (commit 1 is
 * taken), 0x61 alarm armed, 0x62 before commit 2 (before its wait: inside the 0.52 ms gap's slack) always;
 * 0x63 after commit 2 (hybrid bit 29) and 0x64 right before cpu0's CYC_OVRD write (hybrid bit 30) only when asked:
 * a PMU write after commit 2 may collide with the engine's own SPMI traffic.
 */
static void aseq_crumb_raw(struct apple_sleep_seq *s, u8 c, u32 extra_bit)
{
	u32 h = READ_ONCE(hybrid);

	if (!(h & ASEQ_HYBRID_ENTRY2) || (extra_bit && !(h & BIT(extra_bit))))
		return;
	aseq_spmi(s, PMU_BOOT_STAGE, &c, 1, NULL, 0);
}

static void aseq_crumb(struct apple_sleep_seq *s, u64 val, u32 extra_bit)
{
	u8 c = val;

	if (val == 0x63 && (READ_ONCE(hybrid) & ASEQ_HYBRID_STATE_DUMP))
		c = aseq_ps_crumb;
	aseq_crumb_raw(s, c, extra_bit);
}

/* hybrid bit 30: crumb 0x64, right before cpu0's CYC_OVRD write (the last AP instruction before the WFI) */
static void aseq_boot_crumb(void)
{
	struct apple_sleep_seq *s = READ_ONCE(apple_sleep_seq);

	u8 c = 0x64;

	if (!s)
		return;
	if ((READ_ONCE(hybrid) & (ASEQ_HYBRID_STATE_DUMP | BIT(29) | BIT(30))) ==
	    (ASEQ_HYBRID_STATE_DUMP | BIT(29) | BIT(30))) {
		c = aseq_ps_field;
	} else if (READ_ONCE(hybrid) & ASEQ_HYBRID_STATE_DUMP) {
		int stopped = atomic_read(&aseq_stopped), down = atomic_read(&aseq_down);

		if (stopped < (int)nr_cpu_ids - 1)
			c = 0x72;
		else
			c = 0x66 + clamp(stopped - down, 0, 11);
	}
	/* aseq_crumb() writes val; the state value is passed through the same hybrid-bit gating */
	aseq_crumb_raw(s, c, 30);
}

static void aseq_entry2_map(void)
{
	if (!(READ_ONCE(hybrid) & ASEQ_HYBRID_ENTRY2) || aseq_ans_bridge)
		return;
	aseq_ans_bridge = ioremap_np(ASEQ_ANS_BRIDGE_PA, SZ_4K);
}

static void aseq_entry2(struct apple_sleep_seq *s)
{
	unsigned int i, still_busy = 0, unlatched = 0;
	bool ans_on = false, differed = false, bridge_read = false;
	u8 crumb = 0;

	if (!(READ_ONCE(hybrid) & ASEQ_HYBRID_ENTRY2))
		return;

	for (i = 0; i < s->nps; i++) {
		u32 v = readl(s->ps[i].reg), off;

		if (s->ps[i].name && strstr(s->ps[i].name, "ans2") && FIELD_GET(PS_ACTUAL, v) == PS_ON)
			ans_on = true;
		if (!(v & ASEQ_PS_BUSY) || (v & (PS_ACTUAL | PS_TARGET)))
			continue;
		/* A switch still finishing reads BUSY for a moment: only one that stays is a latch */
		if (!readl_poll_timeout_atomic(s->ps[i].reg, v, !(v & ASEQ_PS_BUSY), 1, 1000))
			continue;
		off = v & ~(PS_AUTO_ENABLE | PS_FLAGS | ASEQ_PS_BUSY | ASEQ_PS_UNLATCH | ASEQ_PS_DEV_DISABLE);
		/* m2pro-7.3.4 (b5w): a witness only, aurora's unlatch with ASEQ_HYBRID_ENTRY2_ACT */
		if (READ_ONCE(hybrid) & ASEQ_HYBRID_ENTRY2_ACT) {
			writel(off | ASEQ_PS_UNLATCH, s->ps[i].reg);
			readl_poll_timeout_atomic(s->ps[i].reg, v, !(v & ASEQ_PS_BUSY), 1, 5000);
			writel(off, s->ps[i].reg);
			unlatched++;
		}
		pr_emerg("apple-sleep: entry2: %s BUSY-latched%s: %#x -> %#x\n", s->ps[i].name,
			 unlatched ? ", unlatched" : "", v, readl(s->ps[i].reg));
	}
	for (i = 0; i < s->nps; i++)
		if (readl(s->ps[i].reg) & ASEQ_PS_BUSY)
			still_busy++;

	if (aseq_ans_bridge && ans_on) {
		u32 w[3] = { readl(aseq_ans_bridge), readl(aseq_ans_bridge + ASEQ_BRIDGE_104),
			     readl(aseq_ans_bridge + ASEQ_BRIDGE_108) };

		if (!aseq_entries) {
			memcpy(aseq_ans_first, w, sizeof(w));
		} else {
			unsigned int k;

			for (k = 1; k < 3; k++) {
				u32 off = k == 1 ? ASEQ_BRIDGE_104 : ASEQ_BRIDGE_108;

				if ((w[k] ^ aseq_ans_first[k]) & BIT(0)) {
					differed = true;
					if (READ_ONCE(hybrid) & ASEQ_HYBRID_ENTRY2_ACT)
						writel((w[k] & ~BIT(0)) | (aseq_ans_first[k] & BIT(0)),
						       aseq_ans_bridge + off);
				}
			}
		}
		bridge_read = true;
		pr_emerg("apple-sleep: entry2: entry %u: ANS bridge +0 %#x +104 %#x +108 %#x (first %#x %#x %#x)%s\n",
			 aseq_entries + 1, w[0], w[1], w[2], aseq_ans_first[0], aseq_ans_first[1],
			 aseq_ans_first[2], !differed ? "" :
			 (READ_ONCE(hybrid) & ASEQ_HYBRID_ENTRY2_ACT) ? ", bit 0 put back" : ", bit 0 differs");
	} else {
		pr_emerg("apple-sleep: entry2: entry %u: ANS bridge not read (mapped %d, ANS on %d)\n",
			 aseq_entries + 1, !!aseq_ans_bridge, ans_on);
	}
	pr_emerg("apple-sleep: entry2: entry %u: %u PS words unlatched, %u still BUSY\n", aseq_entries + 1,
		 unlatched, still_busy);

	if (still_busy && differed)
		crumb = 0x5f;
	else if (still_busy)
		crumb = 0x5d;
	else if (differed)
		crumb = 0x5e;
	else
		crumb = bridge_read ? 0x5b : 0x5a;	/* ran, found nothing; 0x5a: but the ANS bridge was not read */
	if (READ_ONCE(hybrid) & ASEQ_HYBRID_STATE_DUMP)
		aseq_dump_ps(s);
	if (aseq_spmi(s, PMU_BOOT_STAGE, &crumb, 1, NULL, 0))
		pr_emerg("apple-sleep: entry2: crumb %#x not written\n", crumb);
	aseq_entries++;
}

static void aseq_op_run(struct apple_sleep_seq *s, const struct apple_sleep_op *op, u64 found,
			unsigned int step)
{
	void __iomem *reg = s->base[op->blk] + op->off;
	u32 v;

	switch (op->kind) {
	case SEQ_W32:
		writel(op->val, reg);
		break;
	case SEQ_W64:
		/* dispext_off: macOS's report words carry the external DCPs' requests until n24 #4 */
		if (s->dispext_done && op->blk == s->soc->report_blk && op->off == s->soc->report_write)
			writeq(op->val & ~((s->dispext_bound & BIT(0) ? 0 :
					    BIT_ULL(s->soc->dispext_report_bit[0])) |
					   (s->dispext_bound & BIT(1) ? 0 :
					    BIT_ULL(s->soc->dispext_report_bit[1]))), reg);
		else
			writeq(op->val, reg);
		break;
	case SEQ_CLR32:
		writel((u32)found & ~(u32)op->val, reg);
		break;
	case SEQ_EDGE_W32:
		writel((u32)op->val, reg);
		break;
	case SEQ_SET32:
	case SEQ_EDGE_SET32:
		writel((u32)found | (u32)op->val, reg);
		break;
	case SEQ_SET64:
		writeq(found | op->val, reg);
		break;
	case SEQ_WAITCLR32:
		/* As ApplePMGR::waitReg32(map, off, mask, 0, 192000): after a perf-state write, after AFR's */
		if (readl_poll_timeout_atomic(reg, v, !(v & (u32)op->val), 1, SEQ_WAIT_US) &&
		    !s->ps_missed++)
			s->ps_missed_step = step;
		s->saved[step] = v;
		break;
	case SEQ_CLACK32:
		if (aseq_clack_wait(reg, &v) && !s->ps_missed++)
			s->ps_missed_step = step;
		if ((op->val & SEQ_CLACK_ZERO) && v) {
			writel(0, reg);
			if (aseq_clack_wait(reg, &v) && !s->ps_missed++)
				s->ps_missed_step = step;
		}
		s->saved[step] = v;
		break;
	case SEQ_R32:
		/* The read is aseq_run's, saved in saved[]: nothing to write */
		break;
	case SEQ_PS_LOWER:
		/* As macOS writes PMP: 0xf0f00ff, then 0xf0f03f0. Writing the flags clears them. */
		v = found & ~(PS_AUTO_ENABLE | PS_FLAGS);
		writel(v, reg);
		writel((v & ~PS_TARGET) | PS_FLAGS, reg);
		aseq_ps_wait(reg, 0);
		break;
	case SEQ_PS_RAISE_AUTO:
		/* As macOS writes APCIE_GE_SYS: 0xf000000, 0xf00000f, 0x1f00000f. */
		v = found & ~(PS_AUTO_ENABLE | PS_FLAGS);
		writel(v, reg);
		v = (v & ~PS_TARGET) | PS_ON;
		writel(v, reg);
		aseq_ps_wait(reg, PS_ON);
		writel(v | PS_AUTO_ENABLE, reg);
		break;
	case SEQ_PS_SET:
	case SEQ_PS_EDGE:
		/* A word to the state macOS has at its edge; a wait that runs out is counted, not fatal */
		v = ((u32)found & ~(SEQ_PS_SET_BITS | PS_FLAGS)) | ((u32)op->val & SEQ_PS_SET_BITS);
		writel(v, reg);
		if (aseq_ps_wait(reg, SEQ_PS_SET_ACTUAL(op->val)) && !s->ps_missed++)
			s->ps_missed_step = step;
		break;
	case SEQ_PS_NO_AUTO:
		/* As read, flags included: SIO_CPU 0x400024f. */
		writel(found & ~PS_AUTO_ENABLE, reg);
		break;
	case SEQ_DELAY:
		udelay(op->val);
		break;
	case SEQ_DEADLINE:
		writel(aseq_deadline(op->val), reg);
		break;
	case SEQ_CPUS_STOP:
		atomic_set(&aseq_stopped, 0);
		atomic_set(&aseq_down, 0);
		aseq_turn_start();
		s->cpus_stop_ret = spin_table_stop_parked();
		/* As on macOS each goes down right after its stop, before the quiesce. */
		aseq_turn_start();
		if (!(READ_ONCE(hybrid) & ASEQ_HYBRID_NATIVE_HOLD))
			spin_table_release_stopped();
		break;
	case SEQ_BOOT_DEEP:
		local_daif_mask();
		if (READ_ONCE(hybrid) & ASEQ_HYBRID_NATIVE_HOLD) {
			/* After commit 2, as macOS: the stopped CPUs go down, cpu0 closes last */
			int us;

			spin_table_release_stopped();
			for (us = 0; us < 5000 &&
			     atomic_read(&aseq_down) < atomic_read(&aseq_stopped); us++)
				udelay(1);
			if (atomic_read(&aseq_down) < atomic_read(&aseq_stopped))
				pr_emerg("apple-sleep: native hold: %d of %d CPUs down at cpu0's request\n",
					 atomic_read(&aseq_down), atomic_read(&aseq_stopped));
		}
		aseq_deep_request(true, true);
		aseq_last_wfi();
	case SEQ_PMU_W8:
	case SEQ_PMU_R:
	case SEQ_PMU_RTC_NOW:
	case SEQ_PMU_ALARM:
		aseq_pmu_run(s, op, step);
		break;
	case SEQ_AIC_MASK:
		/* As on macOS: a raised line would end the last WFI, and the engine waits for it. */
		aic_sleep_mask_all();
		break;
	case SEQ_MARK:
		s->mark = __arch_counter_get_cntvct();
		break;
	case SEQ_WD2:
		writel(0, reg + WDT_CTL);
		writel(0, reg + WDT_COUNT);
		writel((wd2_s ? wd2_s : op->val) * WDT_TICKS_PER_S, reg + WDT_BITE);
		writel(WDT_CTL_RESET, reg + WDT_CTL);
		break;
	case SEQ_ENTRY2:
		aseq_entry2(s);
		break;
	case SEQ_CRUMB:
		aseq_crumb(s, op->val, op->off);
		break;
	case SEQ_GATE:
		break;
	case SEQ_COPROC_IDLE:
		/* Its result shows at the commit: no fallback, so a failed idle leaves it running. */
		s->coproc_ret[op->off] = aseq_coproc_stop(s, op->off);
		s->coproc_idled |= BIT(op->off);
		break;
	case SEQ_COPROC_STOP:
		if (s->coproc_idled & BIT(op->off))
			break;
		s->coproc_ret[op->off] = aseq_coproc_stop(s, op->off);
		reg = s->base[op->blk] + ASC_CPU_CONTROL;
		fallthrough;
	case SEQ_ASC_STOP:
		/*
		 * A gated CPU's registers may not answer: only one whose word isn't off. pd385: the
		 * DCPEXTs run at actual 4, so "fully on" (pd369's test) left them running.
		 */
		v = readl(s->base[op->val >> 32] + (u32)op->val);
		if (FIELD_GET(PS_ACTUAL, v) && (readl(reg) & ASC_CPU_CONTROL_RUN)) {
			/* As macOS stops a DCP: twice (aurora dcp_s2r_cpu_stop) */
			writel(0, reg);
			writel(0, reg);
		}
		break;
	case SEQ_UNTIL:
		while (__arch_counter_get_cntvct() - s->mark <
		       div_u64((u64)op->val * arch_timer_get_cntfrq(), USEC_PER_SEC))
			cpu_relax();
		break;
	}
	dsb(sy);
}

/* A mark with any tag, for what the step's callee recorded (the SEP's report) */
static void aseq_bench_mark_tag(u64 tag)
{
	register u64 x0 asm("x0") = 4;
	register u64 x1 asm("x1") = tag;

	if (!marks || !bench || is_kernel_in_hyp_mode())
		return;
	asm volatile("hvc #0x5332" : "+r"(x0) : "r"(x1) : "memory");
}

static void aseq_bench_mark(struct apple_sleep_seq *s, unsigned int step)
{
	register u64 x0 asm("x0") = 4;
	register u64 x1 asm("x1") = SEQ_MARK_MAGIC | (u64)(s->gate_failed & 0xff) << 24 |
				    (u64)!!s->pmu_ret << 16 | (u64)!!s->ps_missed << 17 |
				    (u64)min(s->ps_missed, 0xffU) << 32 | step;

	if (!marks || !bench || is_kernel_in_hyp_mode())
		return;
	asm volatile("hvc #0x5332" : "+r"(x0) : "r"(x1) : "memory");
}

static void aseq_run(struct apple_sleep_seq *s, const struct apple_sleep_op *ops, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		const struct apple_sleep_op *op = &ops[i];
		u64 found = 0;

		if (!aseq_op_runs(s, op))
			continue;
		/*
		 * A refused gate: no commit, nothing more to the PMU; the deadline takes it from here.
		 * The way back still runs: a refusal before the deadline (the SEP's step comes first)
		 * must not leave cpu0 down with no deadline and no WD2.
		 */
		if (s->gate_failed && op->kind != SEQ_BOOT_DEEP && op->kind != SEQ_DEADLINE &&
		    op->kind != SEQ_WD2)
			continue;
		/* Before the step: the last mark names the step that was reached, and the state so far */
		aseq_bench_mark(s, i);
		if (op->kind == SEQ_SEP_SLEEP) {
			if (!sep_sleep)
				continue;
			s->sep_ret = apple_sleep_enclave_send();
			/* After the stop returned: what its SLEEP got (pm_shim's report), success or not */
			for (unsigned int w = 0; w < APPLE_SLEEP_ENCLAVE_REPORT_WORDS; w++)
				if (apple_sleep_enclave_report[w])
					aseq_bench_mark_tag(apple_sleep_enclave_report[w]);
			if (s->sep_ret) {
				s->gate_failed = SEQ_GATE_SEP;
				s->gate_step = i;
				aseq_bench_mark(s, i);
			}
			continue;
		}
		if (op->kind == SEQ_GATE) {
			s->gate_failed = aseq_gate(s, op->val);
			if (s->gate_failed) {
				s->gate_step = i;
				aseq_bench_mark(s, i);
			}
			continue;
		}
		if (aseq_op_reads(s, op)) {
			found = aseq_read(s->base[op->blk] + op->off, op);
			s->saved[i] = found;
			s->saved_valid[i] = true;
		}
		aseq_op_run(s, op, found, i);
	}
}

static const char *const aseq_kind_names[] = {
	[SEQ_W32] = "W32", [SEQ_W64] = "W64", [SEQ_CLR32] = "CLR32", [SEQ_R32] = "R32", [SEQ_SET32] = "SET32", [SEQ_SET64] = "SET64", [SEQ_WAITCLR32] = "wait-clr32", [SEQ_CLACK32] = "clack32", [SEQ_PS_LOWER] = "PS-lower",
	[SEQ_PS_RAISE_AUTO] = "PS-raise+auto", [SEQ_PS_SET] = "PS-set", [SEQ_PS_NO_AUTO] = "PS-no-auto", [SEQ_PS_EDGE] = "PS-edge", [SEQ_EDGE_SET32] = "edge-set32", [SEQ_EDGE_W32] = "edge-w32",
	[SEQ_DELAY] = "delay", [SEQ_DEADLINE] = "deadline", [SEQ_CPUS_STOP] = "cpus-stop",
	[SEQ_BOOT_DEEP] = "boot-deep", [SEQ_PMU_W8] = "PMU-W8", [SEQ_PMU_R] = "PMU-R",
	[SEQ_PMU_RTC_NOW] = "PMU-RTC-now", [SEQ_PMU_ALARM] = "PMU-alarm", [SEQ_AIC_MASK] = "AIC-mask",
	[SEQ_MARK] = "mark", [SEQ_UNTIL] = "until", [SEQ_GATE] = "gate", [SEQ_ENTRY2] = "entry2", [SEQ_CRUMB] = "crumb", [SEQ_WD2] = "WD2",
	[SEQ_ASC_STOP] = "ASC-stop", [SEQ_COPROC_STOP] = "coproc-stop",
	[SEQ_COPROC_IDLE] = "coproc-idle", [SEQ_SEP_SLEEP] = "SEP-sleep",
};

/*
 * Before the PM core suspends anything: each step this sleep will take, with the word as
 * Linux has it now, for the diff against macOS's list. Nothing is gated yet.
 */
/*
 * Bench, note 84 §42: dispext0/1 run from boot with no driver bound (the firmware is iBoot's,
 * the PMP report entries keep their cpu0/fe/sys on, their no_ps sub-domains are as iBoot left
 * them), until the entry's n24 #4 rows stop them 0.43 s before the commit. 1: those rows run
 * once at boot, after the PMP report's driver has bound; 2: at .begin. The entry skips them
 * then. Every value prints the external DCPs' words once at boot.
 */
static uint dispext_off = 1;
module_param(dispext_off, uint, 0444);
MODULE_PARM_DESC(dispext_off, "bench: dispext0/1's entry rows at boot (1) or .begin (2), 0 at the entry");

#define DISPEXT_TRIES	40	/* x 250 ms for the PMP report's driver */

/* The rows from each external DCP's coproc stop through its last PS word */
static int aseq_dispext_mark(struct apple_sleep_seq *s)
{
	const struct apple_sleep_seq_soc *soc = s->soc;
	unsigned int i;
	bool in = false, d1 = false;

	if (!soc->ndispext)
		return 0;
	s->dispext_rows = devm_bitmap_zalloc(s->dev, soc->nentry, GFP_KERNEL);
	s->dispext1_rows = devm_bitmap_zalloc(s->dev, soc->nentry, GFP_KERNEL);
	if (!s->dispext_rows || !s->dispext1_rows)
		return -ENOMEM;
	for (i = 0; i < soc->nentry; i++) {
		const struct apple_sleep_op *op = &soc->entry[i];

		if (op->kind == SEQ_COPROC_STOP) {
			in = op->blk == soc->dispext_asc[0] ||
			     (soc->ndispext > 1 && op->blk == soc->dispext_asc[1]);
			d1 = soc->ndispext > 1 && op->blk == soc->dispext_asc[1];
		} else if (in && !((op->kind == SEQ_W64 || op->kind == SEQ_PS_LOWER) &&
				 (op->group & (SEQ_G_DISP | SEQ_G_DCPREPORT | SEQ_G_DXSUB)))) {
			in = false;
		}
		if (in)
			__set_bit(i, s->dispext_rows);
		if (in && d1)
			__set_bit(i, s->dispext1_rows);
	}

	return 0;
}

/*
 * Which external DCPs a driver owns (rv-dpswitch round 2, Q4 #1; its batch 15 review): an
 * available `apple,dcpext` node whose coproc registers hold this table's dcpextN-asc block (by
 * reg-name). Ownership goes by the DT, not by binding: appledrm is a module on m2pro, so the
 * boot rows (1 s after the PMP report) may run before dcpext binds, and dispext_done blocks any
 * undo. The rows of an owned one don't run, at boot, .begin or the entry, and the PMP report
 * keeps its request. The bench deletes dcpext's compatible (BENCH_DT_DELPROP), so nothing
 * changes there. Whether a driver is bound only goes to the log. Process context (boot work,
 * .begin).
 */
static void aseq_dispext_owned(struct apple_sleep_seq *s)
{
	const struct apple_sleep_seq_soc *soc = s->soc;
	u8 owned = 0, bound = 0;

	for (unsigned int d = 0; d < soc->ndispext && d < 2; d++) {
		int index = of_property_match_string(s->dev->of_node, "reg-names",
						     soc->blocks[soc->dispext_asc[d]]);
		struct device_node *np;
		struct resource asc;

		if (index < 0 || of_address_to_resource(s->dev->of_node, index, &asc))
			continue;
		for_each_compatible_node(np, NULL, "apple,dcpext") {
			struct platform_device *pdev;
			struct resource r;

			if (!of_device_is_available(np) || of_address_to_resource(np, 0, &r) ||
			    !resource_overlaps(&r, &asc))
				continue;
			owned |= BIT(d);
			pdev = of_find_device_by_node(np);
			if (pdev && device_is_bound(&pdev->dev))
				bound |= BIT(d);
			if (pdev)
				put_device(&pdev->dev);
		}
	}
	if (owned != s->dispext_bound)
		dev_info(s->dev, "dispext: external DCPs a driver owns (rows skipped): %#x, bound now %#x\n",
			 owned, bound);
	s->dispext_bound = owned;
}

/* Each external DCP's CPU control and status (only with its cpu0 word not off) and its PS words */
static void aseq_dispext_print(struct apple_sleep_seq *s, const char *when)
{
	const struct apple_sleep_seq_soc *soc = s->soc;
	char buf[320];
	int len = 0;
	unsigned int i;

	for_each_set_bit(i, s->dispext_rows, soc->nentry) {
		const struct apple_sleep_op *op = &soc->entry[i];

		if (op->kind == SEQ_COPROC_STOP) {
			void __iomem *asc = s->base[op->blk];
			u32 ps = readl(s->base[op->val >> 32] + (u32)op->val);

			if (len)
				dev_info(s->dev, "bench: dispext %s: %s\n", when, buf);
			len = scnprintf(buf, sizeof(buf), "%s cpu0 %#x", soc->blocks[op->blk], ps);
			if (FIELD_GET(PS_ACTUAL, ps))
				len += scnprintf(buf + len, sizeof(buf) - len, " ctl %#x status %#x",
						 readl(asc + ASC_CPU_CONTROL), readl(asc + ASC_CPU_STATUS));
			else
				len += scnprintf(buf + len, sizeof(buf) - len, " (gated, ASC not read)");
		} else if (op->kind == SEQ_PS_LOWER && len) {
			len += scnprintf(buf + len, sizeof(buf) - len, " %x=%#x", op->off,
					 readl(s->base[op->blk] + op->off));
		}
	}
	if (len)
		dev_info(s->dev, "bench: dispext %s: %s\n", when, buf);
	dev_info(s->dev, "bench: dispext %s: PMP report request %#llx ack %#llx status %#llx\n", when,
		 readq(s->base[soc->report_blk] + soc->report_read),
		 readq(s->base[soc->report_blk] + soc->report_actual),
		 readq(s->base[soc->report_blk] + soc->report_status));
}

/* One external DCP's request withdrawn from the PMP report, the others left as they are */
static void aseq_dispext_report(struct apple_sleep_seq *s, unsigned int d)
{
	const struct apple_sleep_seq_soc *soc = s->soc;
	void __iomem *rep = s->base[soc->report_blk];
	u64 bit = BIT_ULL(soc->dispext_report_bit[d]), v;
	int ret;

	writeq(readq(rep + soc->report_read) & ~bit, rep + soc->report_write);
	ret = readq_poll_timeout_atomic(rep + soc->report_actual, v, !(v & bit), 10, 50000);
	if (ret)
		dev_warn(s->dev, "bench: dispext%u: the PMP still acknowledges bit %u (ack %#llx)\n", d,
			 soc->dispext_report_bit[d], v);
}

/* The rows as the entry runs them, each with interrupts off; once per boot */
static void aseq_dispext_run(struct apple_sleep_seq *s, const char *when)
{
	unsigned int i, n = 0;
	unsigned long flags;

	unsigned int d = 0;

	if (s->dispext_done)
		return;
	aseq_dispext_owned(s);

	for_each_set_bit(i, s->dispext_rows, s->soc->nentry) {
		const struct apple_sleep_op *op = &s->soc->entry[i];
		u64 found = 0;

		if (op->kind == SEQ_COPROC_STOP)
			d = op->blk == s->soc->dispext_asc[0] ? 0 : 1;
		if (!aseq_op_runs(s, op))
			continue;
		if (op->kind == SEQ_W64) {
			aseq_dispext_report(s, d);
			n++;
			continue;
		}
		local_irq_save(flags);
		if (aseq_op_reads(s, op))
			found = aseq_read(s->base[op->blk] + op->off, op);
		aseq_op_run(s, op, found, i);
		local_irq_restore(flags);
		n++;
	}
	s->dispext_done = true;
	dev_info(s->dev, "bench: dispext off at %s: %u rows run, the entry skips them\n", when, n);
	aseq_dispext_print(s, "after");
}

static void aseq_dispext_work_fn(struct work_struct *work)
{
	struct apple_sleep_seq *s = container_of(to_delayed_work(work), struct apple_sleep_seq,
						 dispext_work);
	struct device_node *np = of_find_compatible_node(NULL, NULL, "apple,t6020-pmp-v2-report");
	struct platform_device *pdev = np ? of_find_device_by_node(np) : NULL;
	const struct apple_sleep_seq_soc *soc = s->soc;
	void __iomem *rep = s->base[soc->report_blk];
	u64 seed = BIT_ULL(soc->dispext_report_bit[0]) | BIT_ULL(soc->dispext_report_bit[1]);
	bool bound = pdev && device_is_bound(&pdev->dev);

	of_node_put(np);
	if (pdev)
		put_device(&pdev->dev);
	/* The report's driver writes its whole word once the PMP runs: after that, and 1 s more */
	bound = bound && (readq(rep + soc->report_status) & 1) &&
		(readq(rep + soc->report_read) & seed) == seed;
	if (!bound && ++s->dispext_tries < DISPEXT_TRIES) {
		schedule_delayed_work(&s->dispext_work, msecs_to_jiffies(250));
		return;
	}
	if (bound && !s->dispext_settled) {
		s->dispext_settled = true;
		schedule_delayed_work(&s->dispext_work, msecs_to_jiffies(1000));
		return;
	}
	aseq_dispext_print(s, "boot");
	if (dispext_off != 1)
		return;
	if (!bound) {
		dev_err(s->dev, "bench: dispext off at boot: no running PMP with both requests after %u ms, not run\n",
			DISPEXT_TRIES * 250);
		return;
	}
	aseq_dispext_run(s, "boot");
}

static void aseq_report_plan(struct apple_sleep_seq *s)
{
	const struct apple_sleep_seq_soc *soc = s->soc;
	unsigned int i;

	dev_info(s->dev, "%s: groups %#llx of %#llx, perf-regs %s, delays %s, alarm %s\n",
		 dry_run ? "dry run" : "full entry", s->groups, (u64)SEQ_G_ALL,
		 s->groups & SEQ_G_PERF ? "written" : "skipped", delays ? "on" : "off",
		 s->groups & SEQ_G_PMU ? "on" : "off");
	if (s->groups & SEQ_G_PMU)
		dev_info(s->dev, "the RTC alarm: %u s after the entry\n", READ_ONCE(alarm_s));
	for (i = 0; i < soc->nentry; i++) {
		const struct apple_sleep_op *op = &soc->entry[i];
		bool runs = aseq_op_runs(s, op);

		if (aseq_op_pmu(op)) {
			dev_info(s->dev, "seq %2u %s %-13s PMU %#x val %#llx  %s\n", i,
				 runs ? "run " : "skip", aseq_kind_names[op->kind], op->off, op->val,
				 op->what);
			continue;
		}
		/* pd586: a driver that failed its probe left no stop, and the line still read "acked". */
		if (op->kind == SEQ_COPROC_STOP || op->kind == SEQ_COPROC_IDLE) {
			bool reg = op->off < ARRAY_SIZE(s->coproc) &&
				   apple_sleep_coproc_registered(s->coproc[op->off]);

			dev_info(s->dev, "seq %2u %s %-13s %pa = %#llx  %s [%s]\n", i,
				 runs ? "run " : "skip", aseq_kind_names[op->kind], &s->phys[i],
				 op->val, op->what,
				 reg ? "its driver's stop registered" :
				 op->kind == SEQ_COPROC_IDLE ? "no driver stop: nothing sent" :
				 "no driver stop: CPU stop only");
			continue;
		}
		if ((op->kind == SEQ_W32 && op->blk == s->soc->commit_blk) || op->kind == SEQ_WD2 ||
		    op->kind == SEQ_ASC_STOP) {
			dev_info(s->dev, "seq %2u %s %-13s %pa = %#llx  %s\n", i, runs ? "run " : "skip",
				 aseq_kind_names[op->kind], &s->phys[i], op->val, op->what);
			continue;
		}
		if (!aseq_op_writes(op)) {
			dev_info(s->dev, "seq %2u %s %-13s %llu  %s\n", i, runs ? "run " : "skip",
				 aseq_kind_names[op->kind], op->val, op->what);
			continue;
		}
		/* Only the words this sleep writes are read: a skipped one may be gated. */
		if (runs && !aseq_op_reads(s, op))
			dev_info(s->dev, "seq %2u run  %-13s %pa = %#llx (now not read)  %s\n", i,
				 aseq_kind_names[op->kind], &s->phys[i], op->val, op->what);
		else if (runs)
			dev_info(s->dev, "seq %2u run  %-13s %pa = %#llx (now %#llx)  %s\n", i,
				 aseq_kind_names[op->kind], &s->phys[i], op->val,
				 aseq_read(s->base[op->blk] + op->off, op), op->what);
		else
			dev_info(s->dev, "seq %2u skip %-13s %pa = %#llx  %s\n", i,
				 aseq_kind_names[op->kind], &s->phys[i], op->val, op->what);
	}
}

static long aseq_report_plan_fn(void *arg)
{
	struct apple_sleep_seq *s = arg;

	/* pd338: macOS sleeps with the SLC as iBoot left it, off; nothing turns it off yet. */
	s->slc_enable = readl(s->base[s->soc->slc_blk] + s->soc->slc_off);
	dev_info(s->dev, "SLC: mcc plane 0 +%#x = %#x\n", s->soc->slc_off, s->slc_enable);
	aseq_report_plan(s);
	return 0;
}

/*
 * The PMU through the SPMI core, while its controller's driver still runs: the RTC the
 * commit's gate checks against, and the same reads with no PMU write in any mode.
 */
static void aseq_pmu_begin(struct apple_sleep_seq *s)
{
	u8 buf[8] = {}, stage = 0;
	int ret;

	s->rtc_begin_s = 0;
	if (!s->pmu)
		return;
	ret = spmi_ext_register_readl(s->pmu, PMU_RTC_COUNTER, buf, 6);
	s->cnt_begin = __arch_counter_get_cntvct();
	if (!ret)
		ret = spmi_ext_register_readl(s->pmu, PMU_BOOT_STAGE, &stage, 1);
	if (ret) {
		dev_err(s->dev, "PMU read: %d\n", ret);
		return;
	}
	s->rtc_begin_s = (get_unaligned_le64(buf) & GENMASK_ULL(47, 0)) >> 16;
	s->stage_begin = stage;
	dev_info(s->dev, "PMU: RTC %#llx s, boot_stage %#x\n", s->rtc_begin_s, stage);
}

static struct apple_smc *aseq_smc(struct apple_sleep_seq *s)
{
	if (!IS_REACHABLE(CONFIG_MFD_MACSMC) || !s->smc_dev || !device_is_bound(s->smc_dev))
		return NULL;

	return dev_get_drvdata(s->smc_dev);
}

/* Before any device is told, as macOS's slpw opens its device round */
static int aseq_smc_warn(struct apple_sleep_seq *s)
{
	struct apple_smc *smc = aseq_smc(s);
	u8 wake_type = 2;
	int ret;

	if (!smc) {
		dev_err(s->dev, "refused: smc_notify without a bound SMC\n");
		return -ENODEV;
	}
	ret = apple_smc_sleep_seq_warn(smc);
	if (ret)
		return ret;
	if (smc_notify & SEQ_SMC_PMVC) {
		__le32 v = cpu_to_le32(pmvc);

		ret = apple_smc_write(smc, SMC_KEY(pmVC), &v, sizeof(v));
		dev_info(s->dev, "SMC: pmVC = %#x (bytes %4ph): %d\n", pmvc, &v, ret);
		if (ret)
			return ret;
	}
	if (smc_notify & SEQ_SMC_WKTP) {
		ret = apple_smc_write(smc, SMC_KEY(WKTP), &wake_type, sizeof(wake_type));
		if (ret)
			dev_err(s->dev, "WKTP = 2: %d\n", ret);
	}
	dev_info(s->dev, "SMC: slpw%s\n", smc_notify & SEQ_SMC_WKTP ? ", WKTP = 2" : "");
	if (READ_ONCE(hybrid) & APPLE_SLEEP_HYBRID_SMC_EDGE)
		apple_smc_bench_edge_keys(smc, "after slpw", false);

	return ret;
}

/* Read only: the PS words of every pmgr-pwrstate node, the ones not off, a few per line */
static void aseq_ps_census(struct apple_sleep_seq *s)
{
	char line[256];
	unsigned int i, on = 0, len = 0;

	for (i = 0; i < s->nps; i++) {
		u32 v = readl(s->ps[i].reg);

		if (!FIELD_GET(PS_ACTUAL, v) && !FIELD_GET(PS_TARGET, v))
			continue;
		on++;
		len += scnprintf(line + len, sizeof(line) - len, " %s=%#x", s->ps[i].name, v);
		if (len > 180) {
			dev_info(s->dev, "PS on:%s\n", line);
			len = 0;
		}
	}
	if (len)
		dev_info(s->dev, "PS on:%s\n", line);
	dev_info(s->dev, "PS census: %u of %u words not off\n", on, s->nps);
}

static void __iomem *aseq_ioremap(struct device *dev, const struct resource *res);

/* Every apple,t8103-pmgr-pwrstate node: its pmgr block, mapped once each, and its offset */
static int aseq_ps_map(struct apple_sleep_seq *s)
{
	struct { struct device_node *np; void __iomem *base; resource_size_t size; } blk[16];
	unsigned int nblk = 0, n = 0, i;
	struct device_node *np;

	for_each_compatible_node(np, NULL, "apple,t8103-pmgr-pwrstate")
		n++;
	s->ps = devm_kcalloc(s->dev, n, sizeof(*s->ps), GFP_KERNEL);
	if (!s->ps)
		return -ENOMEM;

	for_each_compatible_node(np, NULL, "apple,t8103-pmgr-pwrstate") {
		struct device_node *parent = of_get_parent(np);
		void __iomem *base = NULL;
		resource_size_t size = 0;
		const char *name;
		u32 off;

		for (i = 0; i < nblk; i++)
			if (blk[i].np == parent) {
				base = blk[i].base;
				size = blk[i].size;
			}
		if (!base && nblk < ARRAY_SIZE(blk)) {
			struct resource res;

			if (!of_address_to_resource(parent, 0, &res))
				base = aseq_ioremap(s->dev, &res);
			if (base) {
				size = resource_size(&res);
				blk[nblk].np = parent;
				blk[nblk].size = size;
				blk[nblk++].base = base;
			}
		}
		of_node_put(parent);
		if (!base || of_property_read_u32(np, "reg", &off) ||
		    of_property_read_string(np, "label", &name))
			continue;
		/* pd358: a word at its block's end (soc-east +0xc000 of 0xc000) faulted: only what is mapped */
		if ((resource_size_t)off + sizeof(u32) > size) {
			dev_info(s->dev, "PS census skips %s: +%#x outside its block's %#llx\n", name, off,
				 (unsigned long long)size);
			continue;
		}
		s->ps[s->nps].name = name;
		s->ps[s->nps++].reg = base + off;
	}

	return 0;
}

/* After the devices' noirq suspend, before the CPUs go: slpa and the AP idle notice */
static int aseq_prepare_late(void)
{
	struct apple_sleep_seq *s = apple_sleep_seq;
	struct apple_smc *smc;
	int ret;

	if (ps_census)
		aseq_ps_census(s);

	if (!(smc_notify & SEQ_SMC_SLEEP))
		return 0;
	smc = aseq_smc(s);
	if (!smc)
		return -ENODEV;
	if (READ_ONCE(hybrid) & APPLE_SLEEP_HYBRID_SMC_EDGE)
		apple_smc_bench_edge_keys(smc, "before slpa", true); /* .prepare_late: after noirq */
	apple_sleep_bench_probe(smc, "before slpa", true);
	ret = apple_smc_sleep_seq_commit(smc, SEQ_SMC_ARM_US, SEQ_SMC_IDLE_US,
					 smc_notify & SEQ_SMC_NO_SLPA);
	if (ret)
		dev_err(s->dev, "refused: the SMC didn't take slpa and the notice: %d\n", ret);

	return ret;
}

static const struct apple_sleep_seq_soc t6020_sleep_seq;

/*
 * via_firmware with the SEP (note 79 §4.1, the user's decision 2026-11-17): the guard is narrowed, not dropped.
 * Allowed only where the SEP is told exactly what the reviewed runs told it (pd470/pd545, the S3 series): the early
 * SLEEP or the table's; or with no SEP driver bound. Any other combination, the flag-less corner, is refused.
 */
static const char *aseq_via_firmware_sep(void)
{
	struct device_node *np;
	struct platform_device *pdev;
	bool bound = false;

	/* Asked of the driver, not taken from the param: a driver without it sends nothing */
	if (apple_sleep_bench_sep_sleep_early())
		return apple_sleep_sep_early_wired() ? "early SLEEP" : NULL;
	if (apple_sleep_bench_sep_sleep())
		return "table SLEEP";
	if (!IS_ENABLED(CONFIG_APPLE_SEP))
		return "no SEP driver built";
	np = of_find_compatible_node(NULL, NULL, "apple,sep");
	pdev = np ? of_find_device_by_node(np) : NULL;
	of_node_put(np);
	if (pdev) {
		bound = !!READ_ONCE(pdev->dev.driver);
		put_device(&pdev->dev);
	}
	return bound ? NULL : "no SEP driver bound";
}

static int aseq_begin(suspend_state_t state)
{
	struct apple_sleep_seq *s = apple_sleep_seq;
	int ret;

	s->resumed = false;
	s->groups = aseq_groups();
	WRITE_ONCE(aseq_core_groups, s->groups);
	s->ps_missed = 0;
	s->coproc_idled = 0;
	/* Whose external DCPs these are now: a driver may have bound one since boot */
	if (state == PM_SUSPEND_MEM && s->dispext_rows)
		aseq_dispext_owned(s);
	if (state == PM_SUSPEND_MEM && bench && dispext_off == 2 && s->dispext_rows) {
		aseq_dispext_print(s, "begin");
		aseq_dispext_run(s, "begin");
	}
	if (state == PM_SUSPEND_MEM && (smc_notify & SEQ_SMC_SLEEP)) {
		ret = aseq_smc_warn(s);
		if (ret)
			return ret;
	}
	if (state == PM_SUSPEND_MEM && via_firmware) {
		const char *sep = aseq_via_firmware_sep();

		if (!sep) {
			pr_err("apple-sleep: bench: suspend via firmware refused: a bound SEP driver without its early or table SLEEP\n");
			return -EPERM;
		}
		pm_set_suspend_via_firmware();
		pr_info("apple-sleep: bench: suspend via firmware, SEP: %s\n", sep);
	}
	/*
	 * Tanabota note 57: perf-regs[8] are per-device idle counters (AFNC2_IOA/LS/LW0/LW1 at
	 * +0x160..+0x190, PD AFNC2 at +0x4a0). edge_on bit 8: start them here (entries +0 = 1,
	 * then the bank's +0 = 1) so the edge shows whether AFNC2 ever idles during the entry;
	 * C4 stops the bank as macOS.
	 */
	if (state == PM_SUSPEND_MEM && (edge_on & BIT(8)) && s->soc == &t6020_sleep_seq) {
		void __iomem *pr = s->base[2 /* T6020_SOC, defined below */] + 0x2c000;
		int i;

		for (i = 0; i < 90; i++)
			writel(readl(pr + 0x100 + 0x10 * i) | 1, pr + 0x100 + 0x10 * i);
		writel(readl(pr) | 1, pr);
		pr_info("apple-sleep: bench: perf-regs[8] idle counters started\n");
	}
	/*
	 * pd716/717: SIO's internal fabrics (pmgr[69]/[70], asio_fab 0x39b020000, asio_fab_lite
	 * 0x39b024000-0x39b027fff): 40 words read 0x4 in macOS at the edge and 0x8004 in Linux
	 * (note 58: macOS tunes them from AppleT6020PMGR's figs tables, Linux never). edge_on
	 * bit 9: clear bit 15 in each word that reads 0x8004.
	 */
	if (state == PM_SUSPEND_MEM && (edge_on & BIT(9)) && s->soc == &t6020_sleep_seq) {
		void __iomem *f = ioremap_np(0x39b020000, 0x8000);
		int i, n = 0;

		if (f) {
			for (i = 0; i < 0x8000; i += 4) {
				if (readl(f + i) == 0x8004) {
					writel(0x4, f + i);
					n++;
				}
			}
			iounmap(f);
		}
		pr_info("apple-sleep: bench: asio fabrics: %d words 0x8004 -> 0x4\n", n);
	}
	/*
	 * Tanabota note 59, pd720/721: the axi2af bridges SIO (16, 0x39a000000) and SEP (23,
	 * 0x397000000) hold reset defaults in Linux (+0xc 0xfffff, +0x14.. 0x5a0, +0x400 0xf00008,
	 * +0xa00 0); macOS applies _af_sioaxi2af_figs_1 (= sepaxi2af's) at device power-on.
	 * edge_on bit 10: SIO's bridge, bit 11: the SEP's, at .begin; +0x400 and +0xa00 last.
	 */
	if (state == PM_SUSPEND_MEM && (edge_on & (BIT(10) | BIT(11))) && s->soc == &t6020_sleep_seq) {
		static const u32 figs[][3] = {
			{ 0x000, 0x3, 0x1 }, { 0x00c, 0xfffff, 0xd }, { 0x010, 0xfffff, 0xc },
			{ 0x014, 0xfff, 0x1 }, { 0x018, 0xfff, 0x1 }, { 0x01c, 0xfff, 0x3 },
			{ 0x020, 0xfff, 0x3 }, { 0x024, 0xfff, 0x3 }, { 0x028, 0xfff, 0x3 },
			{ 0x02c, 0xfff, 0x3 },
			{ 0x108, 0x3, 0x1 }, { 0x10c, 0xfffff, 0xd }, { 0x110, 0xfffff, 0xc },
			{ 0x114, 0xfff, 0x1 }, { 0x118, 0xfff, 0x1 }, { 0x11c, 0xfff, 0x3 },
			{ 0x120, 0xfff, 0x3 }, { 0x124, 0xfff, 0x3 }, { 0x128, 0xfff, 0x3 },
			{ 0x12c, 0xfff, 0x3 },
			{ 0x400, 0xc00103ff, 0xc0010010 }, { 0xa00, 0x1ffffff, 0x1ffffff },
		};
		static const phys_addr_t br[2] = { 0x39a000000, 0x397000000 };
		int b, i;

		for (b = 0; b < 2; b++) {
			void __iomem *r;

			if (!(edge_on & BIT(10 + b)))
				continue;
			r = ioremap_np(br[b], 0x1000);
			if (!r)
				continue;
			for (i = 0; i < ARRAY_SIZE(figs); i++)
				writel((readl(r + figs[i][0]) & ~figs[i][1]) | figs[i][2], r + figs[i][0]);
			pr_info("apple-sleep: bench: axi2af %pa tuned, +0x400 %#x +0xa00 %#x\n", &br[b],
				readl(r + 0x400), readl(r + 0xa00));
			iounmap(r);
		}
	}
	/*
	 * Tanabota note 60: before its deep WFI each macOS core unlocks its CoreSight ED (EDLAR
	 * +0xfb0 <- 0xc5acce55) and clears EDPRCR (+0x310, CORENPDRQ: with it set a core emulates
	 * power-down instead of gating). edge_on bit 13: do it for all 12 cores here (all online).
	 */
	if (state == PM_SUSPEND_MEM && (edge_on & BIT(13)) && s->soc == &t6020_sleep_seq) {
		static const phys_addr_t ed[12] = {
			0x210010000, 0x210110000, 0x210210000, 0x210310000,
			0x211010000, 0x211110000, 0x211210000, 0x211310000,
			0x212010000, 0x212110000, 0x212210000, 0x212310000,
		};
		int i;

		for (i = 0; i < 12; i++) {
			void __iomem *r = ioremap_np(ed[i], 0x1000);
			u32 v;

			if (!r)
				continue;
			writel(0xc5acce55, r + 0xfb0);
			v = readl(r + 0x310);
			writel(0, r + 0x310);
			pr_info("apple-sleep: bench: cpu%d EDPRCR %#x -> %#x\n", i, v, readl(r + 0x310));
			iounmap(r);
		}
	}
	/*
	 * pd756/757: nub-spmi1 (0x29e154000, never bound under Linux) has +0x40 NOTIFY_ENABLE
	 * 0x2000001 at macOS's edge and 0 in Linux, as nub-spmi0 had (pd744-746; aurora writes it on
	 * both controllers). edge_on bit 19, non-posted.
	 */
	if (state == PM_SUSPEND_MEM && (edge_on & BIT(19)) && s->soc == &t6020_sleep_seq) {
		void __iomem *r = ioremap_np(0x29e154000, 0x1000);

		if (r) {
			u32 v = readl(r + 0x40);

			writel(0x2000001, r + 0x40);
			pr_info("apple-sleep: bench: nub-spmi1 +0x40 %#x -> %#x, +0x7c %#x\n", v,
				readl(r + 0x40), readl(r + 0x7c));
			iounmap(r);
		}
	}
	if (state == PM_SUSPEND_MEM)
		aseq_pmu_begin(s);
	if (state == PM_SUSPEND_MEM && s->soc == &t6020_sleep_seq)
		aseq_wake_pmu_map();
	if (state == PM_SUSPEND_MEM)
		aseq_entry2_map();
	if (state == PM_SUSPEND_MEM)
		aseq_dump_map(s);
	/*
	 * On the boot CPU, as macOS does all of its entry: the writer of /sys/power/state may be
	 * anywhere (pd335: cpu5, whose read of a cluster word the bench's HV couldn't take).
	 */
	if (state == PM_SUSPEND_MEM)
		work_on_cpu(0, aseq_report_plan_fn, s);

	return 0;
}

/* cpu_suspend()'s finisher: the whole entry, which ends in the boot CPU's last WFI */
static int aseq_finisher(unsigned long arg)
{
	struct apple_sleep_seq *s = (struct apple_sleep_seq *)arg;

	aseq_run(s, s->soc->entry, s->soc->nentry);
	return -EIO;
}

/* wake_pmu's mappings, made at .begin (ioremap may sleep; aseq_resumed runs with interrupts off) */
static void __iomem *aseq_wp_dwi_ps, *aseq_wp_dwi, *aseq_wp_spmi[2];

static void aseq_wake_pmu_map(void)
{
	static const u64 spmi[2] = { 0x29e114000ULL, 0x29e154000ULL };	/* nub-spmi0, nub-spmi1 reg[0] */
	unsigned int i;

	if ((wake_pmu & ASEQ_WAKE_PMU_DWI) && !aseq_wp_dwi_ps)
		aseq_wp_dwi_ps = ioremap_np(0x28e080110ULL, 4);		/* pmgr PS word "dwi" */
	if ((wake_pmu & ASEQ_WAKE_PMU_DWI) && !aseq_wp_dwi)
		aseq_wp_dwi = ioremap_np(0x28e0fc000ULL, 0x100);	/* /arm-io/dwi reg[0]; mapped, not read */
	for (i = 0; i < 2; i++)
		if ((wake_pmu & ASEQ_WAKE_PMU_NOTIFY) && !aseq_wp_spmi[i])
			aseq_wp_spmi[i] = ioremap_np(spmi[i], 0x100);
	if (wake_pmu)
		pr_info("apple-sleep: wake_pmu %#x mapped: dwi ps %d, dwi %d, nub-spmi0 %d, nub-spmi1 %d\n", wake_pmu,
			!!aseq_wp_dwi_ps, !!aseq_wp_dwi, !!aseq_wp_spmi[0], !!aseq_wp_spmi[1]);
}

/* Interrupts off, before the boot_stage write; logs once the console is back (pr_emerg, as aseq_resumed) */
static void aseq_wake_pmu(void)
{
	unsigned int i, n;

	if (wake_pmu & ASEQ_WAKE_PMU_DWI) {
		u32 was = 0, cur = 0;

		if (!aseq_wp_dwi_ps || !aseq_wp_dwi) {
			pr_emerg("apple-sleep: wake_pmu dwi: not mapped, skipped\n");
		} else {
			was = readl(aseq_wp_dwi_ps);
			writel(0x44, aseq_wp_dwi_ps);
			writel(0x4f, aseq_wp_dwi_ps);
			writel(0x1000004f, aseq_wp_dwi_ps);
			for (n = 0; n < 1000; n++) {
				cur = readl(aseq_wp_dwi_ps);
				if (((cur >> 4) & 0xf) == 0xf)
					break;
				udelay(10);
			}
			if (n == 1000) {
				pr_emerg("apple-sleep: wake_pmu dwi: PS %#x -> %#x, actual not f after 10 ms: DWI not written\n",
					 was, cur);
			} else {
				writel(1, aseq_wp_dwi + 0x0);
				writel(0x2ee00, aseq_wp_dwi + 0xd0);
				writel(0x78, aseq_wp_dwi + 0x4);
				writel(0, aseq_wp_dwi + 0x84);
				writel(0x41, aseq_wp_dwi + 0x80);
				pr_emerg("apple-sleep: wake_pmu dwi: PS %#x -> %#x after %u us, DWI +0 <- 1, +0xd0 <- 0x2ee00, +4 <- 0x78, +0x84 <- 0, +0x80 <- 0x41 (PS now %#x)\n",
					 was, cur, n * 10, readl(aseq_wp_dwi_ps));
			}
		}
	}
	if (wake_pmu & ASEQ_WAKE_PMU_NOTIFY) {
		for (i = 0; i < 2; i++) {
			u32 was;

			if (!aseq_wp_spmi[i]) {
				pr_emerg("apple-sleep: wake_pmu nub-spmi%u: not mapped, skipped\n", i);
				continue;
			}
			was = readl(aseq_wp_spmi[i] + 0x40);
			writel(0x3f803031, aseq_wp_spmi[i] + 0x40);
			pr_emerg("apple-sleep: wake_pmu nub-spmi%u +0x40 NOTIFY_ENABLE %#x -> 0x3f803031 (reads %#x)\n",
				 i, was, readl(aseq_wp_spmi[i] + 0x40));
		}
	}
}

/* resume=2: the PM core's stages after a real resume, as RSU|step marks */
static void aseq_resume_mark(struct apple_sleep_seq *s, unsigned int step, u64 data)
{
	if (s && s->resumed && resume == 2)
		aseq_bench_mark_tag(SEQ_RESUME_MAGIC | step | (data & 0xffffff) << 8);
}

/* Back through cpu_resume, MMU on, interrupts off, the other CPUs down */
static void aseq_resumed(struct apple_sleep_seq *s)
{
	u8 stage = s->stage_begin ? s->stage_begin : PMU_BOOT_STAGE_RUNNING;
	u64 resumes, n;

	aseq_bench_mark_tag(SEQ_RESUME_MAGIC | 1);
	dcache_inval_poc((unsigned long)s->mbox, (unsigned long)(s->mbox + 1));
	resumes = READ_ONCE(s->mbox->resumes);
	aseq_wake_pmu();
	if (wake_pmu & ASEQ_WAKE_PMU_STAGE0) {
		stage = 0;
		pr_emerg("apple-sleep: wake_pmu: boot_stage <- 0x00 as macOS (stage_begin %#x)\n", s->stage_begin);
	}
	s->resume_pmu_ret = aseq_spmi(s, PMU_BOOT_STAGE, &stage, 1, NULL, 0);
	aseq_bench_mark_tag(SEQ_RESUME_MAGIC | 2 | (u64)stage << 8 |
			    (u64)((resumes - s->resumes_before) & 0xff) << 16 |
			    (u64)(-s->resume_pmu_ret & 0xff) << 24);
	s->resumed = true;
	pr_emerg("apple-sleep: back from S2R: resumes %llu -> %llu, PMU boot_stage <- %#x: %d\n",
		 s->resumes_before, resumes, stage, s->resume_pmu_ret);
	if (READ_ONCE(hybrid) & ASEQ_HYBRID_NATIVE_EDGE_CNTPCT)
		pr_emerg("apple-sleep: native: regates %llu, edge_cntpct %#llx, wake at %#llx (%llu ms later)\n",
		 READ_ONCE(s->mbox->regates), aseq_edge_cntpct,
		 (u64)__arch_counter_get_cntpct(),
		 div_u64((__arch_counter_get_cntpct() - aseq_edge_cntpct) * 1000,
			 arch_timer_get_cntfrq()));
	if (resume != 1)
		return;
	for (n = 0;; n++) {
		aseq_bench_mark_tag(SEQ_RESUME_MAGIC | 3 | (n & 0xffffff) << 8);
		mdelay(1000);
	}
}

/* apple_sleep.resume: the entry inside cpu_suspend(), resume_pa armed for the hypervisor */
static int aseq_enter_resume(struct apple_sleep_seq *s)
{
	u64 cntkctl = read_sysreg(cntkctl_el1);
	int ret;

	s->resumes_before = READ_ONCE(s->mbox->resumes);
	WRITE_ONCE(s->mbox->resume_pa, __pa_symbol(cpu_resume));
	dcache_clean_poc((unsigned long)s->mbox, (unsigned long)(s->mbox + 1));
	dsb(sy);
	/* The wake really resets the CPU: __cpu_suspend_exit() restores the impdef state */
	pm_set_resume_via_firmware();

	ret = cpu_suspend((unsigned long)s, aseq_finisher);
	if (ret) {
		WRITE_ONCE(s->mbox->resume_pa, 0);
		dcache_clean_poc((unsigned long)s->mbox, (unsigned long)(s->mbox + 1));
		dev_err(s->dev, "the entry ended without the boot CPU's power-down: %d\n", ret);
		return -EIO;
	}

	aseq_resumed(s);

	/* resume=2: what the commit and the reset took that the PM core doesn't put back */
	write_sysreg(cntkctl, cntkctl_el1);
	isb();
	spin_table_stop_finished();
	aic_sleep_restore();
	aseq_resume_mark(s, 4, 0);
	return 0;
}

/*
 * Bench (note 77 §14.127-14.128, hybrid bit 15), after aurora's T6040 fix by František Balázsy
 * (25aeeed6f05f): the power loss resets every PMGR power word; the domains a Linux driver owns come
 * back when their devices resume, but the ones the boot loader left on and nobody claims stay gated
 * (on j416s, measured: dwi, fpwm0, the UARTs, pmgr_soc_ocla). Each word below is kept at .enter, and
 * at .wake (before the noirq resume) those that were fully on (target and actual 0xf) and came back
 * with a lower target are raised again, in address (ADT) order, parents first.
 */
static const struct {
	u64 pa;
	u32 len;
} aseq_ps_restore_ranges[] = {
	{ 0x28e080110ULL, 0x2c },	/* pmgr: dwi .. pmgr_soc_ocla */
	{ 0x2902801e8ULL, 0x1ac },	/* soc-east: fpwm0 .. uart6 (sio_cpu at +0x1e0 and mca from +0x398 out) */
};
#define ASEQ_PS_RESTORE_WORDS	(0x2c / 8 + 1 + 0x1ac / 8 + 1)
static u32 aseq_ps_saved[ASEQ_PS_RESTORE_WORDS];
static bool aseq_ps_saved_valid;

static void aseq_ps_restore_walk(bool save)
{
	unsigned int r, k = 0, raised = 0, failed = 0;

	for (r = 0; r < ARRAY_SIZE(aseq_ps_restore_ranges); r++) {
		void __iomem *p = ioremap_np(aseq_ps_restore_ranges[r].pa, aseq_ps_restore_ranges[r].len + 8);
		u32 off;

		if (!p) {
			k += aseq_ps_restore_ranges[r].len / 8 + 1;
			continue;
		}
		for (off = 0; off <= aseq_ps_restore_ranges[r].len; off += 8, k++) {
			u32 saved = aseq_ps_saved[k], val, cur = 0;
			unsigned int n;

			if (save) {
				aseq_ps_saved[k] = readl(p + off);
				continue;
			}
			if ((saved & 0xff) != 0xff)
				continue;
			val = readl(p + off);
			if ((val & 0xf) == 0xf)
				continue;
			writel((val & ~0xf) | 0xf, p + off);
			for (n = 0; n < 1000; n++) {
				cur = readl(p + off);
				if (((cur >> 4) & 0xf) == 0xf)
					break;
				udelay(10);
			}
			if (n == 1000)
				failed++;
			raised++;
			pr_info("apple-sleep-seq: wake: power word %#llx: %#x at .enter, %#x after the wake, now %#x\n",
				aseq_ps_restore_ranges[r].pa + off, saved, val, cur);
		}
		iounmap(p);
	}
	if (!save)
		pr_info("apple-sleep-seq: wake: %u power word(s) raised again, %u not on\n", raised, failed);
}

static int aseq_enter(suspend_state_t state)
{
	struct apple_sleep_seq *s = apple_sleep_seq;

	/* No resume path yet: the full entry only where the bench's hypervisor catches the wake. */
	if (!dry_run && (!s->mbox || !bench)) {
		dev_err(s->dev, "refused: no resume yet, the full entry runs only on the bench\n");
		return -EOPNOTSUPP;
	}
	if (!dry_run && (s->groups & SEQ_G_COMMIT)) {
		/* The deadline is the way back when a commit doesn't take */
		if (!(s->groups & SEQ_G_DEADLINE)) {
			dev_err(s->dev, "refused: a commit without the SMC deadline\n");
			return -EINVAL;
		}
		/* slc_ok: the boot object left the SLC off, as iBoot leaves it for macOS (pd338) */
		if (!slc_ok) {
			dev_err(s->dev, "refused: no row turns the SLC off (apple_sleep.slc_ok)\n");
			return -EOPNOTSUPP;
		}
		if (s->slc_enable & 1) {
			dev_err(s->dev, "refused: the SLC is on (%#x) despite slc_ok\n", s->slc_enable);
			return -EOPNOTSUPP;
		}
		/* Before anything is written: the SEP driver's .suspend must have staged its SLEEP */
		if (sep_sleep && !apple_sleep_enclave_staged()) {
			dev_err(s->dev, "refused: sep_sleep, but no SEP SLEEP staged\n");
			return -EIO;
		}
		if ((s->groups & SEQ_G_PMU) && !s->rtc_begin_s) {
			dev_err(s->dev, "refused: no PMU RTC from .begin for the gate\n");
			return -EIO;
		}
	}

	/* The PM core enters on the boot CPU, the others offline; the table assumes cpu0. */
	if (smp_processor_id() != 0) {
		dev_err(s->dev, "refused: entered on cpu%d, not the boot CPU\n", smp_processor_id());
		return -EINVAL;
	}

	/* The last refusal: every parked CPU answers, or nothing is written. */
	if (s->groups & SEQ_G_CPUS) {
		s->cpus_hold_ret = spin_table_hold_parked();
		if (s->cpus_hold_ret) {
			dev_err(s->dev, "refused: a CPU didn't answer the hold: %d\n",
				s->cpus_hold_ret);
			return s->cpus_hold_ret;
		}
	}

	if (apple_sleep_bench_hybrid() & APPLE_SLEEP_HYBRID_PS_RESTORE) {
		aseq_ps_restore_walk(true);
		aseq_ps_saved_valid = true;
	}

	if (resume && !dry_run)
		return aseq_enter_resume(s);

	/* Not undone: the dry run ends in the last op's WFI, the clocks parked. */
	aseq_run(s, s->soc->entry, s->soc->nentry);

	/* A table without its last step: nothing parked the boot CPU. */
	dev_err(s->dev, "the entry ended without the boot CPU's power-down\n");
	return -EIO;
}

static void aseq_wake(void)
{
	aseq_resume_mark(apple_sleep_seq, 6, num_online_cpus());
	if (aseq_ps_saved_valid) {
		aseq_ps_saved_valid = false;
		aseq_ps_restore_walk(false);
	}
}

static const struct platform_suspend_ops aseq_suspend_ops = {
	.valid = suspend_valid_only_mem,
	.begin = aseq_begin,
	.prepare_late = aseq_prepare_late,
	.enter = aseq_enter,
	.wake = aseq_wake,
};

static void aseq_syscore_resume(void *data)
{
	aseq_resume_mark(apple_sleep_seq, 5, 0);
}

static const struct syscore_ops aseq_syscore_ops = {
	.resume = aseq_syscore_resume,
};

static struct syscore aseq_syscore = {
	.ops = &aseq_syscore_ops,
};

static int aseq_pm_resume_early(struct device *dev)
{
	aseq_resume_mark(apple_sleep_seq, 7, 0);
	return 0;
}

static int aseq_pm_resume(struct device *dev)
{
	aseq_resume_mark(apple_sleep_seq, 8, 0);
	return 0;
}

static const struct dev_pm_ops aseq_pm_ops = {
	.resume_early = aseq_pm_resume_early,
	.resume = aseq_pm_resume,
};

static void aseq_alive_fn(struct work_struct *work)
{
	if (READ_ONCE(hybrid) & ASEQ_HYBRID_CPUCHECK)
		aseq_cpu_check("wake");
	aseq_resume_mark(apple_sleep_seq, 10, 0);
}
static DECLARE_DELAYED_WORK(aseq_alive_work, aseq_alive_fn);

/*
 * hybrid bit 25: at the wake, last of all (PM_POST_SUSPEND, after the SPMI drivers' resume), the AOP
 * SPMI controllers' NOTIFY_ENABLE (+0x40) back to macOS's awake value; the entry's n24 #12 leaves 0x2000001.
 */
#define ASEQ_HYBRID_AOP_SPMI_AWAKE	BIT(25)
#define ASEQ_AOP_SPMI_NOTIFY		0x40
#define ASEQ_AOP_SPMI_AWAKE		0x3d003031

static void aseq_aop_spmi_awake(struct apple_sleep_seq *s)
{
	static const char * const names[] = { "aop-spmi0", "aop-spmi1" };
	unsigned int i, j;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		for (j = 0; j < s->soc->nblocks; j++) {
			void __iomem *r;
			u32 was;

			if (strcmp(s->soc->blocks[j], names[i]))
				continue;
			r = s->base[j] + ASEQ_AOP_SPMI_NOTIFY;
			was = readl(r);
			writel(ASEQ_AOP_SPMI_AWAKE, r);
			dev_info(s->dev, "%s +0x40 NOTIFY_ENABLE %#x -> %#x at the wake (now %#x)\n",
				 names[i], was, ASEQ_AOP_SPMI_AWAKE, readl(r));
		}
	}
}

/*
 * Bench: where does VR3l drop, at slpa or only at the cut? A read-only line at three points: before
 * slpa (.prepare_late), right after slpa returns (the SMC's commit), after the SMC wake. Off by default.
 */
static bool smc_probe;
module_param(smc_probe, bool, 0644);
MODULE_PARM_DESC(smc_probe, "bench: log VR3l, MEPS and PMU 0x200/0x1300/0x2505 before slpa, after slpa and after the SMC wake");

void apple_sleep_bench_probe(struct apple_smc *smc, const char *tag, bool polled)
{
	static const smc_key keys[] = { SMC_KEY(VR3l), SMC_KEY(MEPS) };
	struct apple_sleep_seq *s = READ_ONCE(apple_sleep_seq);
	static const u16 pmu_regs[] = { 0x200, 0x1300, 0x2505 };
	char line[160];
	char pmu[64];
	int i, len = 0;

	if (!READ_ONCE(smc_probe) || !s)
		return;

	line[0] = 0;
	apple_smc_bench_read_line(smc, keys, ARRAY_SIZE(keys), line, sizeof(line), polled);
	for (i = 0; i < ARRAY_SIZE(pmu_regs); i++) {
		u8 v = 0;
		int ret = aseq_spmi(s, pmu_regs[i], NULL, 0, &v, 1);

		if (ret)
			len += scnprintf(pmu + len, sizeof(pmu) - len, " %#x=err%d", pmu_regs[i], ret);
		else
			len += scnprintf(pmu + len, sizeof(pmu) - len, " %#x=%02x", pmu_regs[i], v);
	}
	dev_info(s->dev, "smc_probe (%s):%s | PMU%s\n", tag, line, pmu);
}
EXPORT_SYMBOL_GPL(apple_sleep_bench_probe);

/* For the SMC's driver: smc_notify's bits above 4 (the wake-time bench switches), 0 without the sequencer */
unsigned int apple_sleep_bench_smc_wake_bits(void)
{
	return READ_ONCE(apple_sleep_seq) ? READ_ONCE(smc_notify) : 0;
}
EXPORT_SYMBOL_GPL(apple_sleep_bench_smc_wake_bits);

/* For the SMC's driver, after its waka at the wake: the value to write to pmVC, if smc_notify bit 3 asks */
bool apple_sleep_bench_pmvc_wake(u32 *value)
{
	if (!READ_ONCE(apple_sleep_seq) || !(READ_ONCE(smc_notify) & SEQ_SMC_PMVC_WAKE))
		return false;
	*value = pmvc_wake != U32_MAX ? pmvc_wake : pmvc;

	return true;
}
EXPORT_SYMBOL_GPL(apple_sleep_bench_pmvc_wake);

static int aseq_pm_notify(struct notifier_block *nb, unsigned long action, void *data)
{
	struct apple_sleep_seq *s = apple_sleep_seq;

	if (action == PM_SUSPEND_PREPARE && s && (READ_ONCE(hybrid) & ASEQ_HYBRID_CPUCHECK_PRE))
		aseq_cpu_check("pre");
	if (action == PM_SUSPEND_PREPARE && s && (READ_ONCE(hybrid) & ASEQ_HYBRID_ENTRY_PSTATE))
		aseq_entry_pstate();
	if (action == PM_POST_SUSPEND && s && s->resumed && resume == 2) {
		aseq_resume_mark(s, 9, 0);
		if (READ_ONCE(hybrid) & ASEQ_HYBRID_AOP_SPMI_AWAKE)
			aseq_aop_spmi_awake(s);
		schedule_delayed_work(&aseq_alive_work, alive_s * HZ);
	}
	return NOTIFY_DONE;
}

static struct notifier_block aseq_pm_nb = {
	.notifier_call = aseq_pm_notify,
};

static int aseq_map_mailbox(struct apple_sleep_seq *s)
{
	struct device_node *chosen = of_find_node_by_path("/chosen");
	u64 pa;
	int ret;

	if (!chosen)
		return -ENODEV;
	ret = of_property_read_u64(chosen, "aurora,s2r-mailbox", &pa);
	of_node_put(chosen);
	if (ret)
		return -ENODEV;

	s->mbox = devm_memremap(s->dev, pa, sizeof(*s->mbox), MEMREMAP_WB);
	if (IS_ERR(s->mbox))
		return PTR_ERR(s->mbox);
	if (s->mbox->magic != AURA_S2R_MAGIC)
		return dev_err_probe(s->dev, -EINVAL, "bad mailbox magic %llx\n", s->mbox->magic);
	if (s->mbox->boot_mpidr != cpu_logical_map(0))
		return dev_err_probe(s->dev, -EINVAL, "mailbox is for CPU %llx, not this boot CPU\n",
				     s->mbox->boot_mpidr);

	return 0;
}

static void aseq_iounmap(void *addr)
{
	iounmap((void __iomem *)addr);
}

static void __iomem *aseq_ioremap(struct device *dev, const struct resource *res)
{
	void __iomem *p;

	if (res->flags & IORESOURCE_MEM_NONPOSTED)
		p = ioremap_np(res->start, resource_size(res));
	else
		p = ioremap(res->start, resource_size(res));
	if (!p || devm_add_action_or_reset(dev, aseq_iounmap, (void __force *)p))
		return NULL;

	return p;
}

static int aseq_map_blocks(struct apple_sleep_seq *s)
{
	const struct apple_sleep_seq_soc *soc = s->soc;
	struct device *dev = s->dev;
	phys_addr_t *start;
	unsigned int i;

	s->base = devm_kcalloc(dev, soc->nblocks, sizeof(*s->base), GFP_KERNEL);
	start = devm_kcalloc(dev, soc->nblocks, sizeof(*start), GFP_KERNEL);
	s->phys = devm_kcalloc(dev, soc->nentry, sizeof(*s->phys), GFP_KERNEL);
	s->saved = devm_kcalloc(dev, soc->nentry, sizeof(*s->saved), GFP_KERNEL);
	s->saved_valid = devm_kcalloc(dev, soc->nentry, sizeof(*s->saved_valid), GFP_KERNEL);
	if (!s->base || !start || !s->phys || !s->saved || !s->saved_valid)
		return -ENOMEM;

	for (i = 0; i < soc->nblocks; i++) {
		struct resource res;
		int index = of_property_match_string(dev->of_node, "reg-names", soc->blocks[i]);

		if (index < 0 || of_address_to_resource(dev->of_node, index, &res))
			return dev_err_probe(dev, -EINVAL, "no %s registers\n", soc->blocks[i]);
		/*
		 * Shared with the drivers of these blocks, so not claimed. Mapped as they map them:
		 * non-posted under the soc bus's nonposted-mmio (pd339: a posted write to nub-spmi0
		 * +0x40 came back as an SError).
		 */
		s->base[i] = aseq_ioremap(dev, &res);
		if (!s->base[i])
			return -ENOMEM;
		start[i] = res.start;
	}

	for (i = 0; i < soc->nentry; i++) {
		const struct apple_sleep_op *op = &soc->entry[i];

		if (!aseq_op_writes(op) && op->kind != SEQ_WD2 && op->kind != SEQ_ASC_STOP &&
		    op->kind != SEQ_COPROC_STOP && op->kind != SEQ_COPROC_IDLE)
			continue;
		if (op->blk >= soc->nblocks)
			return dev_err_probe(dev, -EINVAL, "step %u: no block %u\n", i, op->blk);
		s->phys[i] = start[op->blk] + op->off;
	}

	return 0;
}

static int __apple_sleep_seq_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct apple_sleep_seq *s;
	int ret;

	/* Below EL2 a monitor owns all of this, unless it is the bench's hypervisor. */
	if (!is_kernel_in_hyp_mode() && !bench)
		return -ENODEV;

	/* The last step masks every interrupt line, which needs AIC's room for them. */
	if (!aic_sleep_ready())
		return dev_err_probe(dev, -ENOMEM, "AIC has no sleep masks; no system sleep\n");

	s = devm_kzalloc(dev, sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	s->dev = dev;
	s->soc = of_device_get_match_data(dev);
	if (!s->soc)
		return -ENODEV;

	/* Without the boot object's half a wake would rerun its boot flow: dry runs only. */
	ret = aseq_map_mailbox(s);
	if (ret == -ENODEV && !dry_run) {
		dev_info(dev, "no aurora,s2r-mailbox from the boot object: no deep sleep\n");
		return ret;
	}
	if (ret && ret != -ENODEV)
		return ret;

	ret = aseq_map_blocks(s);
	if (ret)
		return ret;
	ret = aseq_ps_map(s);
	if (ret)
		return ret;
	s->groups = aseq_groups();
	WRITE_ONCE(aseq_core_groups, s->groups);

	for (ret = 0; ret < ARRAY_SIZE(s->coproc); ret++) {
		struct device_node *np = of_parse_phandle(dev->of_node, "apple,coprocs", ret);
		struct platform_device *cp = np ? of_find_device_by_node(np) : NULL;

		of_node_put(np);
		if (cp)
			s->coproc[ret] = &cp->dev;
	}
	ret = 0;

	if (IS_REACHABLE(CONFIG_MFD_MACSMC)) {
		struct device_node *np = of_parse_phandle(dev->of_node, "apple,smc", 0);
		struct platform_device *smc_pdev = np ? of_find_device_by_node(np) : NULL;

		of_node_put(np);
		if (smc_pdev)
			s->smc_dev = &smc_pdev->dev;
	}

	if (IS_REACHABLE(CONFIG_SPMI)) {
		struct device_node *np = of_parse_phandle(dev->of_node, "apple,pmu", 0);

		if (np) {
			s->pmu = spmi_find_device_by_of_node(np);
			of_node_put(np);
			if (IS_ERR(s->pmu))
				s->pmu = NULL;
		}
		if (!s->pmu)
			return dev_err_probe(dev, -EPROBE_DEFER, "no PMU on SPMI yet\n");
	}

	ret = spin_table_set_power_ops(&aseq_cpu_power_ops);
	if (ret)
		return dev_err_probe(dev, ret, "cannot control CPU power\n");

	ret = aseq_dispext_mark(s);
	if (ret)
		return ret;
	if (bench && s->dispext_rows) {
		INIT_DELAYED_WORK(&s->dispext_work, aseq_dispext_work_fn);
		schedule_delayed_work(&s->dispext_work, 0);
	}

	apple_sleep_seq = s;
	suspend_set_ops(&aseq_suspend_ops);
	if (resume == 2) {
		register_syscore(&aseq_syscore);
		register_pm_notifier(&aseq_pm_nb);
	}

	dev_info(dev, "%s, %s; %u entry steps\n",
		 s->mbox ? "boot object mailbox" : "no boot object mailbox",
		 dry_run ? "dry run" : (s->mbox && bench) ? "full entry, the bench catches the wake" :
		 "full entry refused: no resume yet",
		 s->soc->nentry);

	return 0;
}

/*
 * T6020 (M2 Pro, j416s). Blocks: ADT /arm-io/pmgr reg[0], [1], [2], [4], [38], [40], [44],
 * [45], [46]; the clusters' reg[8]/[10] (E), [17]/[19] (P0), [26]/[28] (P1); /arm-io/aop-gpio0
 * reg[0], aop-spmi0/1 reg[0].
 */
enum {
	T6020_PMGR,	/* reg[0] 0x28e080000: PS, cluster-ctl, pwrgate, CPU_START, 0x4c000 */
	T6020_AON,	/* reg[1] 0x29e280000: WD0, the SMC deadline */
	T6020_SOC,	/* reg[2] 0x290280000: SIO, SIO_CPU, APCIE_GE_SYS PS */
	T6020_CLK,	/* reg[4] 0x28e000000: ClkGen-SOC muxes */
	T6020_COMMIT,	/* reg[38] 0x29e5c0000 */
	T6020_PMGR40,	/* reg[40] 0x28e20c000 */
	T6020_AFR,	/* reg[44] 0x404e80000 */
	T6020_PMS,	/* reg[45] 0x28e3c0000: PMS SRAM, the PMP report */
	T6020_PLL,	/* reg[46] 0x28e224000 */
	T6020_DVFS_E, T6020_CPM_E, T6020_DVFS_P0, T6020_CPM_P0, T6020_DVFS_P1, T6020_CPM_P1,
	T6020_AOP_GPIO, T6020_AOP_SPMI0, T6020_AOP_SPMI1,
	T6020_NUB_SPMI,	/* nub-spmi0 0x29e114000: the PMU (SID 0xb) */
	T6020_MCC,	/* /arm-io/mcc reg[2] 0x200000000, plane 0: the SLC enable */
	T6020_WAKE,	/* pmgr reg[7] 0x29e004000: the wake masks (G14) */
	T6020_GFX_ASC,	/* /arm-io/gfx-asc 0x406400000 */
	T6020_DCP_ASC, T6020_DCPEXT0_ASC, T6020_DCPEXT1_ASC,	/* the DCPs' coproc: disp0, dispext0, dispext1 */
	T6020_ANS_ASC,	/* /arm-io/ans 0x347400000 */
	T6020_SIO_ASC,	/* /arm-io/sio 0x39bc00000 */
	T6020_MTP_ASC,	/* /arm-io/mtp 0x2a9400000 */
	T6020_MCC0, T6020_MCC1, T6020_MCC2, T6020_MCC3,	/* ADT mcc reg 2-5: the error words to +0x156010, the DCS blocks to +0x800040 */
	T6020_ANS_NVME,	/* /arm-io/ans reg[3] 0x34bcc0000: the NVMe controller's registers */
	/* cpu-impl-reg + 0x5000 of each core: E 0x2100n5000, P0 0x2110n5000, P1 0x2120n5000 */
	T6020_CORE0, T6020_CORE1, T6020_CORE2, T6020_CORE3, T6020_CORE4, T6020_CORE5,
	T6020_CORE6, T6020_CORE7, T6020_CORE8, T6020_CORE9, T6020_CORE10, T6020_CORE11,
	T6020_BLOCKS
};

static const char *const t6020_blocks[T6020_BLOCKS] = {
	[T6020_PMGR] = "pmgr", [T6020_AON] = "aon", [T6020_SOC] = "soc-east",
	[T6020_CLK] = "clkgen", [T6020_COMMIT] = "commit", [T6020_PMGR40] = "pmgr40",
	[T6020_AFR] = "afr", [T6020_PMS] = "pms", [T6020_PLL] = "pll",
	[T6020_DVFS_E] = "dvfs-e", [T6020_CPM_E] = "cpm-e",
	[T6020_DVFS_P0] = "dvfs-p0", [T6020_CPM_P0] = "cpm-p0",
	[T6020_DVFS_P1] = "dvfs-p1", [T6020_CPM_P1] = "cpm-p1",
	[T6020_AOP_GPIO] = "aop-gpio", [T6020_AOP_SPMI0] = "aop-spmi0",
	[T6020_AOP_SPMI1] = "aop-spmi1", [T6020_NUB_SPMI] = "nub-spmi",
	[T6020_MCC] = "mcc-plane0", [T6020_WAKE] = "wake", [T6020_GFX_ASC] = "gfx-asc",
	[T6020_DCP_ASC] = "dcp-asc", [T6020_DCPEXT0_ASC] = "dcpext0-asc",
	[T6020_DCPEXT1_ASC] = "dcpext1-asc", [T6020_ANS_ASC] = "ans-asc",
	[T6020_SIO_ASC] = "sio-asc", [T6020_MTP_ASC] = "mtp-asc",
	[T6020_MCC0] = "mcc0", [T6020_MCC1] = "mcc1", [T6020_MCC2] = "mcc2", [T6020_MCC3] = "mcc3",
	[T6020_ANS_NVME] = "ans-nvme",
	[T6020_CORE0] = "core0", [T6020_CORE1] = "core1", [T6020_CORE2] = "core2",
	[T6020_CORE3] = "core3", [T6020_CORE4] = "core4", [T6020_CORE5] = "core5",
	[T6020_CORE6] = "core6", [T6020_CORE7] = "core7", [T6020_CORE8] = "core8",
	[T6020_CORE9] = "core9", [T6020_CORE10] = "core10", [T6020_CORE11] = "core11",
};

#define OP(k, b, o, v, g, w) \
	{ .kind = SEQ_##k, .blk = T6020_##b, .off = (o), .val = (v), .group = SEQ_G_##g, .what = (w) }
#define W32(b, o, v, g, w)	OP(W32, b, o, v, g, w)
#define W64(b, o, v, g, w)	OP(W64, b, o, v, g, w)
#define DELAY(us, g, w)		OP(DELAY, PMGR, 0, us, g, w)
#define CLACK(o, f, w)		OP(CLACK32, PMGR, T6020_CLUSTER_CTL + (o), SEQ_CLACK_BIT | (f), CLACK, \
				   "C11 cluster-ctl ack " w)
#define PMU(k, reg, v, g, w)	OP(k, NUB_SPMI, reg, v, g, w)
#define T6020_PMU_SID		0xb


#define T6020_PS_PMP		0x2c8
#define T6020_PS_PMS_SRAM	0x2d0
#define T6020_PS_SIO		0x1c0
#define T6020_PS_SIO_CPU	0x1e0
#define T6020_PS_APCIE_GE_SYS	0x420
/* pmgr ps-regs[12] (reg[2] +0x400) psidx 1, 3, 5 */
#define T6020_PS_APCIE_ST_SYS	0x408
#define T6020_PS_APCIE_GP_SYS	0x418
#define T6020_PS_APCIE_PHY_SW	0x428
/* nub_spmi0 in AON (reg[1]): ps-regs[0] (+0) psidx 12 */
#define T6020_PS_NUB_SPMI0	0x60
/* The MTP island in AON (reg[1]): ps-regs[0] (+0) psidx 22, 30; ps-regs[1] (+0x100) psidx 0, 3, 4, 5 */
#define T6020_PS_MTP_FABRIC	0xb0
#define T6020_PS_MTP_BASE	0xf0
#define T6020_PS_MTP_SPI0	0x100
#define T6020_PS_MTP_CPU	0x118
#define T6020_PS_MTP_SCM_FABRIC	0x120
#define T6020_PS_MTP_SRAM	0x128
#define T6020_PS_AFR		0x100
/* The display fabric: AFNC2_* in soc-east (pmgr reg[2]), AFNC1_LW2 in pmgr reg[0] */
#define T6020_PS_AFNC2_IOA	0x160
#define T6020_PS_AFNC2_LS	0x168
#define T6020_PS_AFNC2_LW0	0x170
#define T6020_PS_AFNC2_LW1	0x178
#define T6020_PS_AFNC1_LW2	0x210
#define T6020_CLUSTER_CTL	0x8000		/* cluster-ctl-offset 0x88000 from reg[4] */
#define T6020_CPU_START		0x28000		/* misc-cores-offset 0xa8000 from reg[4] */
#define T6020_PWRGATE		0xc030		/* next to pwrgate-regs reg 0 +0xc03c */
#define T6020_ACC		0x660		/* cluster + 0x20660 */
#define T6020_DVFS_CMD		0x20		/* cluster + 0x20020 */
#define T6020_CPM		0x8080		/* cluster + 0x48080 */
#define T6020_PMP_REPORT	0x11000		/* PMS SRAM's soc-device report */
#define T6020_PMS_LEVEL(n)	(0x11080 + 8 * (n))
#define T6020_PMS_SLEEP		0x1834c
#define PERF_ZERO		0x2000000000000000ULL

/* A cluster's quiesce (C5), in pd212's order: ACC, CPM, DVFS, then the three gates. */
#define T6020_CLUSTER(c, dvfs, w)						\
	W64(DVFS_##c, T6020_ACC, 0, CLUSTER, "n24 #21 C5 " w " ACC"),			\
	W64(CPM_##c, T6020_CPM, 0, CLUSTER, "n24 #21 C5 " w " CPM"),			\
	OP(WAITCLR32, DVFS_##c, T6020_DVFS_CMD, 0x80000000, APSCWAIT,		\
	   "C5 " w " DVFS CMD pending clear before (_waitAPSCPending)"),		\
	W64(DVFS_##c, T6020_DVFS_CMD, dvfs, CLUSTER, "n24 #21 C5 " w " DVFS CMD"),	\
	OP(WAITCLR32, DVFS_##c, T6020_DVFS_CMD, 0x80000000, APSCWAIT,		\
	   "C5 " w " DVFS CMD pending clear after (_waitAPSCPending)"),		\
	W32(PMGR, T6020_PWRGATE + 0x0, 0x80000000, CLUSTER, "n24 #21 C5 " w " pwrgate 0"), \
	W32(PMGR, T6020_PWRGATE + 0x4, 0x80000000, CLUSTER, "n24 #21 C5 " w " pwrgate 1"), \
	W32(PMGR, T6020_PWRGATE + 0x8, 0x80000000, CLUSTER, "n24 #21 C5 " w " pwrgate 2")

/* A DCS block, channel c of MCC instance m (mcc[m] + 0x200000 + 0x200000 c): macOS's edge bits only */
#define T6020_DCS(c)		(0x200000 + 0x200000 * (c))
#define T6020_DCSPG(m, c)							\
	OP(SET32, MCC##m, T6020_DCS(c) + 0x1c, 0x1000, DCSPG,			\
	   "DCSPG mcc" #m " dcs" #c " +0x1c |= bit 12 (macOS edge 0x70a1100)"),	\
	OP(CLR32, MCC##m, T6020_DCS(c) + 0x18, 0x2, DCSPG,			\
	   "DCSPG mcc" #m " dcs" #c " +0x18 &= ~bit 1 (macOS edge 0x1)")

/*
 * macOS's entry from slpa on (note 24 phases B and C), in its order. Every address was
 * resolved against j416s's ADT by name (Tanabota notes/sleep/tools/s0-t6020-table.py).
 * What isn't here: rows 1-10 (the IOP phase, S1b); the PMU's boot stage 0x50 and RTC alarm
 * and the AIC mask between the commits (#11, #31-32, S2); WD2, which the commit itself
 * loads with 60 s.
 */
#define T6020_COPROC_STOP(i, asc, psb, pso, g, w) \
	OP(COPROC_STOP, asc, i, SEQ_PS_AT(T6020_##psb, pso), g, w)
#define PSOFF(b, o, g, w)	OP(PS_LOWER, b, o, 0, g, w)

/* A co-processor down as macOS's phase A takes it (pd252): its CPU stopped, then its words, children first */
#define T6020_ASC_STOP(asc, psb, pso, g, w) \
	OP(ASC_STOP, asc, ASC_CPU_CONTROL, SEQ_PS_AT(T6020_##psb, pso), g, w)

/*
 * DXSUB (note 47): the display blocks' sub-domains the ADT marks no_ps (no OS node, no DT node
 * in Linux). At the DISPLAY write (pd558/559, 1 of 1 each) DISPEXT0/1's BE, GP0-2, PPP and DSC
 * read 0x1f0003ff/0x3ff in Linux (on, iBoot's) and 0xf000300/0x300 in macOS (off), while their
 * SYS/FE/CPU0 are off in both; the pwrgate table's status bits for the same 12 switches
 * follow. macOS's AP writes none of them from -683 ms on (pd252/pd404), so they are off before
 * its entry. Lowered here after each DCP's CPU stop, children before CPU0/FE/SYS; PS_LOWER
 * gives macOS's word (flags 9:8 left set by the gating).
 */
#define DXSUB(o, n)	OP(PS_LOWER, PMGR, o, 0, DXSUB, "DXSUB " n " PS off (macOS 0xf000300/0x300 at DISPLAY)")

static const struct apple_sleep_op t6020_entry[] = {
	/*
	 * PGWAKE (note 47): the pwrgate page's first word, aurora's pwrgate_wake[0] on T8140/T8132.
	 * macOS writes it 0x80000000 at every wake (+8.08 ms, the first pmgr[0] write; note 25,
	 * 2 of 2) and reads it so at the DISPLAY write (pd558); Linux never writes it and reads 0
	 * (pd559). It is set for macOS's whole entry, so it goes first here.
	 */
	W32(PMGR, 0xc000, 0x80000000, PGWAKE, "PGWAKE pwrgate +0 <- 0x80000000 (macOS's wake value)"),
	/*
	 * pd427/pd428's readlist at the census edge: words macOS has and Linux doesn't, all
	 * clusters still up here.
	 * - N25C: each core's cpu-impl-reg +0x5008/+0x5000 and each cluster's CPM +0x9008/+0x9000,
	 *   0 in Linux. macOS writes these from its reset path (note 25 R1a/R15a: 0xffbf.., 1;
	 *   0xff5f.., 1); its edge reads 0x18200007f356e9f / 0xff1fffffe2ca9161, which look like
	 *   the hardware's own state, so these are the values it writes, not the ones it reads.
	 * - DVFMMAP: the P clusters' ACC->DVFM map, 2..17 on macOS (first-acc-dvfm-map-state 2),
	 *   0..15 in Linux.
	 * - THROTTLE: CPM +0x250, +0x270, +0x8400 differ only in bit 63, set on macOS.
	 */
	W64(CORE0, 0x8, 0xffbfffffffffffffULL, N25C, "N25-C core0 +0x5008 (macOS reset path)"),
	W64(CORE0, 0x0, 1, N25C, "N25-C core0 +0x5000 <- 1"),
	W64(CPM_E, 0x9008, 0xff5fffffffffffffULL, N25C, "N25-C E CPM +0x9008 (macOS reset path)"),
	W64(CPM_E, 0x9000, 1, N25C, "N25-C E CPM +0x9000 <- 1"),
	W64(CORE1, 0x8, 0xffbfffffffffffffULL, N25C, "N25-C core1 +0x5008 (macOS reset path)"),
	W64(CORE1, 0x0, 1, N25C, "N25-C core1 +0x5000 <- 1"),
	W64(CORE2, 0x8, 0xffbfffffffffffffULL, N25C, "N25-C core2 +0x5008 (macOS reset path)"),
	W64(CORE2, 0x0, 1, N25C, "N25-C core2 +0x5000 <- 1"),
	W64(CORE3, 0x8, 0xffbfffffffffffffULL, N25C, "N25-C core3 +0x5008 (macOS reset path)"),
	W64(CORE3, 0x0, 1, N25C, "N25-C core3 +0x5000 <- 1"),
	W64(CORE4, 0x8, 0xffbfffffffffffffULL, N25C, "N25-C core4 +0x5008 (macOS reset path)"),
	W64(CORE4, 0x0, 1, N25C, "N25-C core4 +0x5000 <- 1"),
	W64(CPM_P0, 0x9008, 0xff5fffffffffffffULL, N25C, "N25-C P0 CPM +0x9008 (macOS reset path)"),
	W64(CPM_P0, 0x9000, 1, N25C, "N25-C P0 CPM +0x9000 <- 1"),
	W64(CORE5, 0x8, 0xffbfffffffffffffULL, N25C, "N25-C core5 +0x5008 (macOS reset path)"),
	W64(CORE5, 0x0, 1, N25C, "N25-C core5 +0x5000 <- 1"),
	W64(CORE6, 0x8, 0xffbfffffffffffffULL, N25C, "N25-C core6 +0x5008 (macOS reset path)"),
	W64(CORE6, 0x0, 1, N25C, "N25-C core6 +0x5000 <- 1"),
	W64(CORE7, 0x8, 0xffbfffffffffffffULL, N25C, "N25-C core7 +0x5008 (macOS reset path)"),
	W64(CORE7, 0x0, 1, N25C, "N25-C core7 +0x5000 <- 1"),
	W64(CORE8, 0x8, 0xffbfffffffffffffULL, N25C, "N25-C core8 +0x5008 (macOS reset path)"),
	W64(CORE8, 0x0, 1, N25C, "N25-C core8 +0x5000 <- 1"),
	W64(CPM_P1, 0x9008, 0xff5fffffffffffffULL, N25C, "N25-C P1 CPM +0x9008 (macOS reset path)"),
	W64(CPM_P1, 0x9000, 1, N25C, "N25-C P1 CPM +0x9000 <- 1"),
	W64(CORE9, 0x8, 0xffbfffffffffffffULL, N25C, "N25-C core9 +0x5008 (macOS reset path)"),
	W64(CORE9, 0x0, 1, N25C, "N25-C core9 +0x5000 <- 1"),
	W64(CORE10, 0x8, 0xffbfffffffffffffULL, N25C, "N25-C core10 +0x5008 (macOS reset path)"),
	W64(CORE10, 0x0, 1, N25C, "N25-C core10 +0x5000 <- 1"),
	W64(CORE11, 0x8, 0xffbfffffffffffffULL, N25C, "N25-C core11 +0x5008 (macOS reset path)"),
	W64(CORE11, 0x0, 1, N25C, "N25-C core11 +0x5000 <- 1"),
	W64(DVFS_P0, 0x500, 2, DVFMMAP, "P0 DVFM map slot 0 <- 2"),
	W64(DVFS_P0, 0x508, 3, DVFMMAP, "P0 DVFM map slot 1 <- 3"),
	W64(DVFS_P0, 0x510, 4, DVFMMAP, "P0 DVFM map slot 2 <- 4"),
	W64(DVFS_P0, 0x518, 5, DVFMMAP, "P0 DVFM map slot 3 <- 5"),
	W64(DVFS_P0, 0x520, 6, DVFMMAP, "P0 DVFM map slot 4 <- 6"),
	W64(DVFS_P0, 0x528, 7, DVFMMAP, "P0 DVFM map slot 5 <- 7"),
	W64(DVFS_P0, 0x530, 8, DVFMMAP, "P0 DVFM map slot 6 <- 8"),
	W64(DVFS_P0, 0x538, 9, DVFMMAP, "P0 DVFM map slot 7 <- 9"),
	W64(DVFS_P0, 0x540, 10, DVFMMAP, "P0 DVFM map slot 8 <- 10"),
	W64(DVFS_P0, 0x548, 11, DVFMMAP, "P0 DVFM map slot 9 <- 11"),
	W64(DVFS_P0, 0x550, 12, DVFMMAP, "P0 DVFM map slot 10 <- 12"),
	W64(DVFS_P0, 0x558, 13, DVFMMAP, "P0 DVFM map slot 11 <- 13"),
	W64(DVFS_P0, 0x560, 14, DVFMMAP, "P0 DVFM map slot 12 <- 14"),
	W64(DVFS_P0, 0x568, 15, DVFMMAP, "P0 DVFM map slot 13 <- 15"),
	W64(DVFS_P0, 0x570, 16, DVFMMAP, "P0 DVFM map slot 14 <- 16"),
	W64(DVFS_P0, 0x578, 17, DVFMMAP, "P0 DVFM map slot 15 <- 17"),
	W64(DVFS_P1, 0x500, 2, DVFMMAP, "P1 DVFM map slot 0 <- 2"),
	W64(DVFS_P1, 0x508, 3, DVFMMAP, "P1 DVFM map slot 1 <- 3"),
	W64(DVFS_P1, 0x510, 4, DVFMMAP, "P1 DVFM map slot 2 <- 4"),
	W64(DVFS_P1, 0x518, 5, DVFMMAP, "P1 DVFM map slot 3 <- 5"),
	W64(DVFS_P1, 0x520, 6, DVFMMAP, "P1 DVFM map slot 4 <- 6"),
	W64(DVFS_P1, 0x528, 7, DVFMMAP, "P1 DVFM map slot 5 <- 7"),
	W64(DVFS_P1, 0x530, 8, DVFMMAP, "P1 DVFM map slot 6 <- 8"),
	W64(DVFS_P1, 0x538, 9, DVFMMAP, "P1 DVFM map slot 7 <- 9"),
	W64(DVFS_P1, 0x540, 10, DVFMMAP, "P1 DVFM map slot 8 <- 10"),
	W64(DVFS_P1, 0x548, 11, DVFMMAP, "P1 DVFM map slot 9 <- 11"),
	W64(DVFS_P1, 0x550, 12, DVFMMAP, "P1 DVFM map slot 10 <- 12"),
	W64(DVFS_P1, 0x558, 13, DVFMMAP, "P1 DVFM map slot 11 <- 13"),
	W64(DVFS_P1, 0x560, 14, DVFMMAP, "P1 DVFM map slot 12 <- 14"),
	W64(DVFS_P1, 0x568, 15, DVFMMAP, "P1 DVFM map slot 13 <- 15"),
	W64(DVFS_P1, 0x570, 16, DVFMMAP, "P1 DVFM map slot 14 <- 16"),
	W64(DVFS_P1, 0x578, 17, DVFMMAP, "P1 DVFM map slot 15 <- 17"),
	OP(SET64, CPM_E, 0x250, BIT_ULL(63), THROTTLE, "E CPM +0x250 |= bit 63 (macOS edge)"),
	OP(SET64, CPM_E, 0x270, BIT_ULL(63), THROTTLE, "E CPM +0x270 |= bit 63 (macOS edge)"),
	OP(SET64, CPM_E, 0x8400, BIT_ULL(63), THROTTLE, "E CPM +0x8400 |= bit 63 (macOS edge)"),
	OP(SET64, CPM_P0, 0x250, BIT_ULL(63), THROTTLE, "P0 CPM +0x250 |= bit 63 (macOS edge)"),
	OP(SET64, CPM_P0, 0x270, BIT_ULL(63), THROTTLE, "P0 CPM +0x270 |= bit 63 (macOS edge)"),
	OP(SET64, CPM_P0, 0x8400, BIT_ULL(63), THROTTLE, "P0 CPM +0x8400 |= bit 63 (macOS edge)"),
	OP(SET64, CPM_P1, 0x250, BIT_ULL(63), THROTTLE, "P1 CPM +0x250 |= bit 63 (macOS edge)"),
	OP(SET64, CPM_P1, 0x270, BIT_ULL(63), THROTTLE, "P1 CPM +0x270 |= bit 63 (macOS edge)"),
	OP(SET64, CPM_P1, 0x8400, BIT_ULL(63), THROTTLE, "P1 CPM +0x8400 |= bit 63 (macOS edge)"),
	/*
	 * A: the co-processors macOS has off at its edge and Linux leaves on (pd366's census).
	 * macOS idles each over RTKit first; that idle is not here: its CPU is stopped as is.
	 */
	/*
	 * DCPREPORT (note 46): aurora's sleep_display_off() writes T8140/T8132's PMC "pmc-dcp" word
	 * (the DCPs still powered, macOS ends at 0) per display after its CPU stop and before its
	 * PS. t6020's is the PMP report (PMS SRAM +0x11000, bits by iop-pmp-nub soc-device: 8/9
	 * PACC0/1, 10 AGX, 13 DISP0, 14 DISPEXT0, 15 DISPEXT1). macOS writes it whole, 2 of 2
	 * (pd252, pd404): 0xe300 before GFX, then 0xc300/0x8300/0x300 before each DCP's CPU0 PS.
	 * The C5' writes later give 0x200 and 0 as before. No display pwrgate pair: macOS's AP
	 * writes none of the ADT pwrgate-regs words in that window (0 of 2).
	 */
	W64(PMS, T6020_PMP_REPORT, 0xe300, DCPREPORT, "PMP report: AGX withdrawn (macOS -538.4 ms)"),
	T6020_ASC_STOP(GFX_ASC, AFR, 0x108, GFX, "n24 #7 GPU CPU stop"),
	OP(PS_LOWER, AFR, 0x108, 0, GFX, "n24 #7 GFX PS off (macOS -534 ms)"),
	/*
	 * MTPSTOP (note 49): at the commit (pd583/584) macOS's mtp_cpu reads 0x1000030f (AUTO,
	 * actual 0) and the island is AUTO-gated (base, scm_fabric, spi0, sram 0x1400024f; fabric
	 * 0x1000030f); Linux's all read 0x1f0000ff, MTPAUTO set: the MTP's CPU still runs.
	 * macOS's only MTP message in its entry is AP 0x201 (SET_AP_PWR_STATE IDLE), the first
	 * IOP it tells, ~8 ms before the DCP round (note 17, pd154; b2, b3, o3d: 4 of 4): no IOP
	 * state change, no CPU stop, no PS write; the firmware idles and the hardware gates it.
	 * The bench kernel binds no driver to it (no APPLE_RTKIT_HELPER): iBoot's firmware runs
	 * with no host. Here: the driver's stop if one registered (apple,coprocs[4]; rtkit-helper
	 * registers none), else the bare CPU_CONTROL stop if mtp_cpu is not off; then the island,
	 * children first, to macOS's settable bits, each waiting on its own PS word for macOS's
	 * actual state, a miss counted. Nothing in this kernel touches the MTP after it: the
	 * device callbacks (dart-mtp's save included) ran before .enter, which doesn't return.
	 */
	/*
	 * MTPIDLE (note 49): macOS's own way, through rtkit-helper's registered stop: AP 0x201
	 * polled and acked, no IOP state, no CPU stop. Then MTPSTOP's CPU stop does nothing and
	 * only its island AUTO waits run. Not registered (no driver): nothing is sent, and the
	 * commit's mtp_cpu shows it. MTPSTOP alone with the driver bound: the AP idle, then the stop.
	 */
	OP(COPROC_IDLE, MTP_ASC, 4, SEQ_PS_AT(T6020_AON, T6020_PS_MTP_CPU), MTPIDLE,
	   "MTPIDLE mtp: AP 0x201 by its driver, polled for the ack (macOS -253 ms, before the DCPs)"),
	T6020_COPROC_STOP(4, MTP_ASC, AON, T6020_PS_MTP_CPU, MTPSTOP,
			  "MTPSTOP mtp: CPU stop (macOS: AP 0x201 only, before the DCPs)"),
	OP(PS_SET, AON, T6020_PS_MTP_CPU, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x0), MTPSTOP,
	   "MTPSTOP mtp_cpu AUTO, actual 0 (macOS at the commit 0x1000030f)"),
	OP(PS_SET, AON, T6020_PS_MTP_SRAM, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x4), MTPSTOP,
	   "MTPSTOP mtp_sram AUTO, actual 4 (macOS at the commit 0x1400024f)"),
	OP(PS_SET, AON, T6020_PS_MTP_SCM_FABRIC, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x4), MTPSTOP,
	   "MTPSTOP mtp_scm_fabric AUTO, actual 4 (macOS at the commit 0x1400024f)"),
	OP(PS_SET, AON, T6020_PS_MTP_SPI0, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x4), MTPSTOP,
	   "MTPSTOP mtp_spi0 AUTO, actual 4 (macOS at the commit 0x1400024f)"),
	OP(PS_SET, AON, T6020_PS_MTP_BASE, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x4), MTPSTOP,
	   "MTPSTOP mtp_base AUTO, actual 4 (macOS at the commit 0x1400024f)"),
	OP(PS_SET, AON, T6020_PS_MTP_FABRIC, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x0), MTPSTOP,
	   "MTPSTOP mtp_fabric AUTO, actual 0 (macOS at the commit 0x1000030f)"),
	T6020_COPROC_STOP(0, DCP_ASC, SOC, 0x1d8, DISP, "n24 #4 disp0: RTKit idle, CPU stop"),
	W64(PMS, T6020_PMP_REPORT, 0xc300, DCPREPORT, "PMP report: DISP0 withdrawn (macOS -457.7 ms)"),
	OP(PS_LOWER, SOC, 0x1d8, 0, DISP, "n24 #4 disp0_cpu0 off (macOS -451.7 ms)"),
	OP(PS_LOWER, SOC, 0x1d0, 0, DISP, "n24 #4 disp0_fe off"),
	OP(PS_LOWER, SOC, 0x1b0, 0, DISP, "n24 #4 disp0_sys off (-447.8 ms)"),
	T6020_COPROC_STOP(1, DCPEXT0_ASC, PMGR, 0x2d8, DISP, "n24 #4 dispext0: RTKit idle, CPU stop"),
	W64(PMS, T6020_PMP_REPORT, 0x8300, DCPREPORT, "PMP report: DISPEXT0 withdrawn (macOS -439.7 ms)"),
	DXSUB(0x350, "dispext0_be"), DXSUB(0x358, "dispext0_gp0"), DXSUB(0x360, "dispext0_gp1"),
	DXSUB(0x368, "dispext0_gp2"), DXSUB(0x370, "dispext0_ppp"), DXSUB(0x398, "dispext0_dsc"),
	OP(PS_LOWER, PMGR, 0x2d8, 0, DISP, "n24 #4 dispext0_cpu0 off (-435.5 ms)"),
	OP(PS_LOWER, PMGR, 0x2c0, 0, DISP, "n24 #4 dispext0_fe off"),
	OP(PS_LOWER, PMGR, 0x258, 0, DISP, "n24 #4 dispext0_sys off (-434.5 ms)"),
	T6020_COPROC_STOP(2, DCPEXT1_ASC, PMGR, 0x2b8, DISP, "n24 #4 dispext1: RTKit idle, CPU stop"),
	W64(PMS, T6020_PMP_REPORT, 0x300, DCPREPORT, "PMP report: DISPEXT1 withdrawn (macOS -430.8 ms)"),
	DXSUB(0x328, "dispext1_be"), DXSUB(0x330, "dispext1_gp0"), DXSUB(0x338, "dispext1_gp1"),
	DXSUB(0x340, "dispext1_gp2"), DXSUB(0x348, "dispext1_ppp"), DXSUB(0x380, "dispext1_dsc"),
	OP(PS_LOWER, PMGR, 0x2b8, 0, DISP, "n24 #4 dispext1_cpu0 off (-430.5 ms)"),
	OP(PS_LOWER, PMGR, 0x2b0, 0, DISP, "n24 #4 dispext1_fe off"),
	OP(PS_LOWER, PMGR, 0x248, 0, DISP, "n24 #4 dispext1_sys off"),
	/*
	 * pd384/385's census: ANS runs in Linux (its driver is a module the bench doesn't load, so
	 * nothing owns its RTKit) and is stopped at macOS's edge with its word on. A bare stop.
	 * Then every word on only in Linux, children first (ADT parents); not atc0_common and
	 * atc0_usb_aon, the hypervisor's debug link. Their macOS time is before the logs: off at
	 * runtime.
	 */
	/*
	 * AIC 1832 is ANS's NVMe controller line (/arm-io/ans interrupts[4]), pending at Linux's
	 * edge only: these kernels have no NVMe driver, so nothing consumes its completions. macOS's
	 * IONVMeController deletes its queues at sleep (EnterLowPowerMode -> ShutdownNVMe) and masks
	 * through NVMe INTMS (+0x0c, SetInterruptMask; INTMC +0x10 unmasks). Without a driver to
	 * delete queues, mask every vector at the source while ans2/apcie_st_sys are still on
	 * (pd385: both on). The state reads are for the plan's saved[].
	 */
	OP(R32, ANS_NVME, 0x14, 0, NVMEMASK, "ANS NVMe CC"),
	OP(R32, ANS_NVME, 0x1c, 0, NVMEMASK, "ANS NVMe CSTS"),
	W32(ANS_NVME, 0x0c, 0xffffffff, NVMEMASK, "ANS NVMe INTMS <- all: AIC 1832 masked at the controller"),
	OP(R32, ANS_NVME, 0x0c, 0, NVMEMASK, "ANS NVMe interrupt mask after INTMS"),
	T6020_ASC_STOP(ANS_ASC, SOC, 0x1a8, LXONLY, "pd385 ANS CPU stop (no driver, no RTKit idle)"),
	PSOFF(PMGR, 0x278, LXONLY, "pd385 atc0_pcie off"),
	PSOFF(PMGR, 0x288, LXONLY, "pd385 atc1_pcie off"),
	PSOFF(PMGR, 0x230, LXONLY, "pd385 atc1_common off"),
	PSOFF(PMGR, 0x298, LXONLY, "pd385 atc2_pcie off"),
	PSOFF(PMGR, 0x238, LXONLY, "pd385 atc2_common off"),
	PSOFF(PMGR, 0x2a8, LXONLY, "pd385 atc3_pcie off"),
	PSOFF(PMGR, 0x240, LXONLY, "pd385 atc3_common off"),
	PSOFF(AON, 0x98, LXONLY, "pd385 atc1_usb_aon off"),
	PSOFF(AON, 0xa0, LXONLY, "pd385 atc2_usb_aon off"),
	PSOFF(AON, 0xa8, LXONLY, "pd385 atc3_usb_aon off"),
	PSOFF(SOC, 0x4010, LXONLY, "pd385 dprx off"),
	PSOFF(SOC, 0x1f0, LXONLY, "pd385 fpwm1 off"),
	PSOFF(SOC, 0x1f8, LXONLY, "pd385 fpwm2 off"),
	PSOFF(SOC, 0x228, LXONLY, "pd385 i2c5 off"),
	PSOFF(SOC, 0x230, LXONLY, "pd385 i2c6 off (macOS -121.7 ms)"),
	PSOFF(SOC, 0x238, LXONLY, "pd385 i2c7 off"),
	PSOFF(SOC, 0x250, LXONLY, "pd385 sio_spmi0 off"),
	PSOFF(SOC, 0x258, LXONLY, "pd385 sio_spmi1 off"),
	PSOFF(SOC, 0x260, LXONLY, "pd385 sio_spmi2 off"),
	PSOFF(AON, 0x78, LXONLY, "pd385 msg off"),
	PSOFF(AON, 0x130, LXONLY, "pd385 mtp_dma off"),
	PSOFF(AON, 0x108, LXONLY, "pd385 mtp_i2cm0 off"),
	PSOFF(AON, 0x110, LXONLY, "pd385 mtp_uart0 off"),
	PSOFF(PMGR, 0x390, LXONLY, "pd385 trace_fab off"),

	/* n24 row 9: the SEP's cmsgSLEEP, macOS's last co-processor before slpa (only with sep_sleep) */
	OP(SEP_SLEEP, PMGR, 0, 0, COMMIT, "n24 #9 SEP cmsgSLEEP 2 through its driver"),

	/* After IOCPUSleepKernel, 0.28 s before the alarm (pd145): the write, then macOS's read-back */
	PMU(PMU_W8, PMU_BOOT_STAGE, PMU_BOOT_STAGE_SLEEP, PMU, "n24 #11 PMU boot_stage 0x50"),
	PMU(PMU_R, PMU_BOOT_STAGE, 1, PMU, "n24 #11 PMU boot_stage read back"),

	/* B: the sleep actions */
	/*
	 * G24: wdt reg[3], aurora's "AP deadline" on T8140/T6040. macOS's edge reads 4 (pd212,
	 * pd252), Linux's 0 (pd342): macOS writes 4 at every wake, right before its first deadline
	 * feed (note 25 R13, 4 of 4), and nothing writes it on Linux.
	 */
	W32(AON, 0x20008, 4, APDL, "G24 aon-misc+0x08 = 4, macOS's value at its edge"),
	OP(DEADLINE, AON, 0x2002c, 10, DEADLINE, "n24 #11 SMC deadline at the WDT sleep action"),
	W32(AOP_SPMI1, 0x40, 0x2000001, SPMI, "n24 #12 aop-spmi1 NOTIFY_ENABLE"),
	W32(AOP_SPMI0, 0x40, 0x2000001, SPMI, "n24 #12 aop-spmi0 NOTIFY_ENABLE"),
	/*
	 * SIOGATE (pd532/540/541): at the DISPLAY cluster-ctl write macOS's SIO and SIO_CPU both
	 * read 0x1400024f (AUTO, target f, PS_MIN 0, actual 4) and afnc2_lw1, SIO's parent, can
	 * drop; Linux's SIO reads 0x1f0000ff (actual f), SIO_CPU 0xf000200 (apple-sio bound, off at
	 * runtime) or 0x1f0000ff (no driver). macOS gets there from the SIO sleep action in
	 * IOCPUSleepKernel, before PMPv2 (note 35 §1): AP 0x201 + IOP 0x201 over RTKit (note 17,
	 * pd154), no CPU stop traced, no PS write until C11/C12. Here: the driver's stop if one
	 * registered (apple,coprocs[3]), else the bare CPU_CONTROL stop if SIO_CPU is not off;
	 * then SIO_CPU and SIO, child first, to macOS's settable bits, each waiting on its own PS
	 * word for actual 4, a miss counted.
	 */
	T6020_COPROC_STOP(3, SIO_ASC, SOC, T6020_PS_SIO_CPU, SIOGATE,
			  "SIOGATE sio: RTKit idle, CPU stop (macOS's SIO sleep action)"),
	OP(PS_SET, SOC, T6020_PS_SIO_CPU, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x4), SIOGATE,
	   "SIOGATE SIO_CPU AUTO, target f, actual 4 (macOS at DISPLAY 0x1400024f)"),
	OP(PS_SET, SOC, T6020_PS_SIO, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x4), SIOGATE,
	   "SIOGATE SIO AUTO, target f, actual 4 (macOS at DISPLAY 0x1400024f)"),
	W64(PMS, T6020_PMS_LEVEL(0), PERF_ZERO, PMP, "n24 #13 PMS SRAM +0x11080"),
	W64(PMS, T6020_PMS_LEVEL(1), PERF_ZERO, PMP, "n24 #13 PMS SRAM +0x11088"),
	W64(PMS, T6020_PMS_LEVEL(2), PERF_ZERO, PMP, "n24 #13 PMS SRAM +0x11090"),
	W64(PMS, T6020_PMS_LEVEL(4), PERF_ZERO, PMP, "n24 #13 PMS SRAM +0x110a0"),
	W64(PMS, T6020_PMS_LEVEL(0), PERF_ZERO, PMP, "n24 #13 PMS SRAM +0x11080 again"),
	W64(PMS, T6020_PMS_LEVEL(1), PERF_ZERO, PMP, "n24 #13 PMS SRAM +0x11088 again"),
	W64(PMS, T6020_PMS_LEVEL(2), PERF_ZERO, PMP, "n24 #13 PMS SRAM +0x11090 again"),
	W64(PMS, T6020_PMS_LEVEL(4), PERF_ZERO, PMP, "n24 #13 PMS SRAM +0x110a0 again"),
	W32(PMS, T6020_PMS_SLEEP, 0x10000, PMP, "n24 #13 PMS SRAM +0x1834c"),
	OP(PS_LOWER, PMGR, T6020_PS_PMP, 0, PMP, "n24 #14 PMP PS off"),
	OP(PS_LOWER, PMGR, T6020_PS_PMS_SRAM, 0, PMP, "n24 #15 PMS_SRAM PS off"),
	OP(CPUS_STOP, PMGR, T6020_CPU_START, 0, CPUS, "n24 #16 secondaries stop, cpu1..11, deep WFI"),

	/* C: the quiesce chain */
	W32(AOP_GPIO, 0x900, 0xffffffff, GPIOIC, "n24 #17 C1 aop-gpio0 +0x900"),
	W32(AOP_GPIO, 0x904, 0xffffffff, GPIOIC, "n24 #17 C1 aop-gpio0 +0x904"),
	W32(AOP_GPIO, 0x908, 0xffffffff, GPIOIC, "n24 #17 C1 aop-gpio0 +0x908"),
	OP(PS_RAISE_AUTO, SOC, T6020_PS_APCIE_GE_SYS, 0, PCIE, "n24 #18 C2 APCIE_GE_SYS up"),
	OP(DEADLINE, AON, 0x2002c, 10, DEADLINE, "n24 #19 C3 SMC deadline at the WDT quiesce"),
	W32(AON, 0x4400c, 0, WDT, "n24 #19 C3 WD0 CTL"),
	/*
	 * n24 #29, on t6020: macOS's AppleT6020PlatformErrorHandler at its platform quiesce, after
	 * the watchdog's and the SLC's actions and before the SEP's, the PMGR's and commit 1
	 * (pd304 111.025 s): _amccEnableErrors(false), per MCC instance, planes 0-3 then the
	 * non-plane words, each enable & ~(set | force_off) then its status <- 0 (13.7.8 static;
	 * the masks _amccGenerateEnableMask's; pd406/407 confirmed the offsets and macOS's 0s).
	 * The DCS and IOA disables and its interrupt disable that follow are not here yet.
	 */
	OP(CLR32, MCC0, 0x21000, 0xb7bffdff, MCCERR, "mcc0 plane0 error enable 0: & ~set & ~force_off"),
	W32(MCC0, 0x22000, 0, MCCERR, "mcc0 plane0 error status 0 <- 0"),
	OP(CLR32, MCC0, 0x21008, 0x3f00, MCCERR, "mcc0 plane0 error enable 1: & ~set & ~force_off"),
	W32(MCC0, 0x22008, 0, MCCERR, "mcc0 plane0 error status 1 <- 0"),
	OP(CLR32, MCC0, 0x21010, 0x10001, MCCERR, "mcc0 plane0 error enable 2: & ~set & ~force_off"),
	W32(MCC0, 0x22010, 0, MCCERR, "mcc0 plane0 error status 2 <- 0"),
	OP(CLR32, MCC0, 0x61000, 0xb7bffdff, MCCERR, "mcc0 plane1 error enable 0: & ~set & ~force_off"),
	W32(MCC0, 0x62000, 0, MCCERR, "mcc0 plane1 error status 0 <- 0"),
	OP(CLR32, MCC0, 0x61008, 0x3f00, MCCERR, "mcc0 plane1 error enable 1: & ~set & ~force_off"),
	W32(MCC0, 0x62008, 0, MCCERR, "mcc0 plane1 error status 1 <- 0"),
	OP(CLR32, MCC0, 0x61010, 0x10001, MCCERR, "mcc0 plane1 error enable 2: & ~set & ~force_off"),
	W32(MCC0, 0x62010, 0, MCCERR, "mcc0 plane1 error status 2 <- 0"),
	OP(CLR32, MCC0, 0xa1000, 0xb7bffdff, MCCERR, "mcc0 plane2 error enable 0: & ~set & ~force_off"),
	W32(MCC0, 0xa2000, 0, MCCERR, "mcc0 plane2 error status 0 <- 0"),
	OP(CLR32, MCC0, 0xa1008, 0x3f00, MCCERR, "mcc0 plane2 error enable 1: & ~set & ~force_off"),
	W32(MCC0, 0xa2008, 0, MCCERR, "mcc0 plane2 error status 1 <- 0"),
	OP(CLR32, MCC0, 0xa1010, 0x10001, MCCERR, "mcc0 plane2 error enable 2: & ~set & ~force_off"),
	W32(MCC0, 0xa2010, 0, MCCERR, "mcc0 plane2 error status 2 <- 0"),
	OP(CLR32, MCC0, 0xe1000, 0xb7bffdff, MCCERR, "mcc0 plane3 error enable 0: & ~set & ~force_off"),
	W32(MCC0, 0xe2000, 0, MCCERR, "mcc0 plane3 error status 0 <- 0"),
	OP(CLR32, MCC0, 0xe1008, 0x3f00, MCCERR, "mcc0 plane3 error enable 1: & ~set & ~force_off"),
	W32(MCC0, 0xe2008, 0, MCCERR, "mcc0 plane3 error status 1 <- 0"),
	OP(CLR32, MCC0, 0xe1010, 0x10001, MCCERR, "mcc0 plane3 error enable 2: & ~set & ~force_off"),
	W32(MCC0, 0xe2010, 0, MCCERR, "mcc0 plane3 error status 2 <- 0"),
	OP(CLR32, MCC0, 0x155000, 0xfffffff, MCCERR, "mcc0 non-plane error enable 0: & ~set & ~force_off"),
	W32(MCC0, 0x156000, 0, MCCERR, "mcc0 non-plane error status 0 <- 0"),
	OP(CLR32, MCC0, 0x155008, 0xff0f0f, MCCERR, "mcc0 non-plane error enable 1: & ~set & ~force_off"),
	W32(MCC0, 0x156008, 0, MCCERR, "mcc0 non-plane error status 1 <- 0"),
	OP(CLR32, MCC0, 0x155010, 0xffffffff, MCCERR, "mcc0 non-plane error enable 2: & ~set & ~force_off"),
	W32(MCC0, 0x156010, 0, MCCERR, "mcc0 non-plane error status 2 <- 0"),
	OP(CLR32, MCC1, 0x21000, 0xb7bffdff, MCCERR, "mcc1 plane0 error enable 0: & ~set & ~force_off"),
	W32(MCC1, 0x22000, 0, MCCERR, "mcc1 plane0 error status 0 <- 0"),
	OP(CLR32, MCC1, 0x21008, 0x3f00, MCCERR, "mcc1 plane0 error enable 1: & ~set & ~force_off"),
	W32(MCC1, 0x22008, 0, MCCERR, "mcc1 plane0 error status 1 <- 0"),
	OP(CLR32, MCC1, 0x21010, 0x10001, MCCERR, "mcc1 plane0 error enable 2: & ~set & ~force_off"),
	W32(MCC1, 0x22010, 0, MCCERR, "mcc1 plane0 error status 2 <- 0"),
	OP(CLR32, MCC1, 0x61000, 0xb7bffdff, MCCERR, "mcc1 plane1 error enable 0: & ~set & ~force_off"),
	W32(MCC1, 0x62000, 0, MCCERR, "mcc1 plane1 error status 0 <- 0"),
	OP(CLR32, MCC1, 0x61008, 0x3f00, MCCERR, "mcc1 plane1 error enable 1: & ~set & ~force_off"),
	W32(MCC1, 0x62008, 0, MCCERR, "mcc1 plane1 error status 1 <- 0"),
	OP(CLR32, MCC1, 0x61010, 0x10001, MCCERR, "mcc1 plane1 error enable 2: & ~set & ~force_off"),
	W32(MCC1, 0x62010, 0, MCCERR, "mcc1 plane1 error status 2 <- 0"),
	OP(CLR32, MCC1, 0xa1000, 0xb7bffdff, MCCERR, "mcc1 plane2 error enable 0: & ~set & ~force_off"),
	W32(MCC1, 0xa2000, 0, MCCERR, "mcc1 plane2 error status 0 <- 0"),
	OP(CLR32, MCC1, 0xa1008, 0x3f00, MCCERR, "mcc1 plane2 error enable 1: & ~set & ~force_off"),
	W32(MCC1, 0xa2008, 0, MCCERR, "mcc1 plane2 error status 1 <- 0"),
	OP(CLR32, MCC1, 0xa1010, 0x10001, MCCERR, "mcc1 plane2 error enable 2: & ~set & ~force_off"),
	W32(MCC1, 0xa2010, 0, MCCERR, "mcc1 plane2 error status 2 <- 0"),
	OP(CLR32, MCC1, 0xe1000, 0xb7bffdff, MCCERR, "mcc1 plane3 error enable 0: & ~set & ~force_off"),
	W32(MCC1, 0xe2000, 0, MCCERR, "mcc1 plane3 error status 0 <- 0"),
	OP(CLR32, MCC1, 0xe1008, 0x3f00, MCCERR, "mcc1 plane3 error enable 1: & ~set & ~force_off"),
	W32(MCC1, 0xe2008, 0, MCCERR, "mcc1 plane3 error status 1 <- 0"),
	OP(CLR32, MCC1, 0xe1010, 0x10001, MCCERR, "mcc1 plane3 error enable 2: & ~set & ~force_off"),
	W32(MCC1, 0xe2010, 0, MCCERR, "mcc1 plane3 error status 2 <- 0"),
	OP(CLR32, MCC1, 0x155000, 0xfffffff, MCCERR, "mcc1 non-plane error enable 0: & ~set & ~force_off"),
	W32(MCC1, 0x156000, 0, MCCERR, "mcc1 non-plane error status 0 <- 0"),
	OP(CLR32, MCC1, 0x155008, 0xff0f0f, MCCERR, "mcc1 non-plane error enable 1: & ~set & ~force_off"),
	W32(MCC1, 0x156008, 0, MCCERR, "mcc1 non-plane error status 1 <- 0"),
	OP(CLR32, MCC1, 0x155010, 0xffffffff, MCCERR, "mcc1 non-plane error enable 2: & ~set & ~force_off"),
	W32(MCC1, 0x156010, 0, MCCERR, "mcc1 non-plane error status 2 <- 0"),
	OP(CLR32, MCC2, 0x21000, 0xb7bffdff, MCCERR, "mcc2 plane0 error enable 0: & ~set & ~force_off"),
	W32(MCC2, 0x22000, 0, MCCERR, "mcc2 plane0 error status 0 <- 0"),
	OP(CLR32, MCC2, 0x21008, 0x3f00, MCCERR, "mcc2 plane0 error enable 1: & ~set & ~force_off"),
	W32(MCC2, 0x22008, 0, MCCERR, "mcc2 plane0 error status 1 <- 0"),
	OP(CLR32, MCC2, 0x21010, 0x10001, MCCERR, "mcc2 plane0 error enable 2: & ~set & ~force_off"),
	W32(MCC2, 0x22010, 0, MCCERR, "mcc2 plane0 error status 2 <- 0"),
	OP(CLR32, MCC2, 0x61000, 0xb7bffdff, MCCERR, "mcc2 plane1 error enable 0: & ~set & ~force_off"),
	W32(MCC2, 0x62000, 0, MCCERR, "mcc2 plane1 error status 0 <- 0"),
	OP(CLR32, MCC2, 0x61008, 0x3f00, MCCERR, "mcc2 plane1 error enable 1: & ~set & ~force_off"),
	W32(MCC2, 0x62008, 0, MCCERR, "mcc2 plane1 error status 1 <- 0"),
	OP(CLR32, MCC2, 0x61010, 0x10001, MCCERR, "mcc2 plane1 error enable 2: & ~set & ~force_off"),
	W32(MCC2, 0x62010, 0, MCCERR, "mcc2 plane1 error status 2 <- 0"),
	OP(CLR32, MCC2, 0xa1000, 0xb7bffdff, MCCERR, "mcc2 plane2 error enable 0: & ~set & ~force_off"),
	W32(MCC2, 0xa2000, 0, MCCERR, "mcc2 plane2 error status 0 <- 0"),
	OP(CLR32, MCC2, 0xa1008, 0x3f00, MCCERR, "mcc2 plane2 error enable 1: & ~set & ~force_off"),
	W32(MCC2, 0xa2008, 0, MCCERR, "mcc2 plane2 error status 1 <- 0"),
	OP(CLR32, MCC2, 0xa1010, 0x10001, MCCERR, "mcc2 plane2 error enable 2: & ~set & ~force_off"),
	W32(MCC2, 0xa2010, 0, MCCERR, "mcc2 plane2 error status 2 <- 0"),
	OP(CLR32, MCC2, 0xe1000, 0xb7bffdff, MCCERR, "mcc2 plane3 error enable 0: & ~set & ~force_off"),
	W32(MCC2, 0xe2000, 0, MCCERR, "mcc2 plane3 error status 0 <- 0"),
	OP(CLR32, MCC2, 0xe1008, 0x3f00, MCCERR, "mcc2 plane3 error enable 1: & ~set & ~force_off"),
	W32(MCC2, 0xe2008, 0, MCCERR, "mcc2 plane3 error status 1 <- 0"),
	OP(CLR32, MCC2, 0xe1010, 0x10001, MCCERR, "mcc2 plane3 error enable 2: & ~set & ~force_off"),
	W32(MCC2, 0xe2010, 0, MCCERR, "mcc2 plane3 error status 2 <- 0"),
	OP(CLR32, MCC2, 0x155000, 0xfffffff, MCCERR, "mcc2 non-plane error enable 0: & ~set & ~force_off"),
	W32(MCC2, 0x156000, 0, MCCERR, "mcc2 non-plane error status 0 <- 0"),
	OP(CLR32, MCC2, 0x155008, 0xff0f0f, MCCERR, "mcc2 non-plane error enable 1: & ~set & ~force_off"),
	W32(MCC2, 0x156008, 0, MCCERR, "mcc2 non-plane error status 1 <- 0"),
	OP(CLR32, MCC2, 0x155010, 0xffffffff, MCCERR, "mcc2 non-plane error enable 2: & ~set & ~force_off"),
	W32(MCC2, 0x156010, 0, MCCERR, "mcc2 non-plane error status 2 <- 0"),
	OP(CLR32, MCC3, 0x21000, 0xb7bffdff, MCCERR, "mcc3 plane0 error enable 0: & ~set & ~force_off"),
	W32(MCC3, 0x22000, 0, MCCERR, "mcc3 plane0 error status 0 <- 0"),
	OP(CLR32, MCC3, 0x21008, 0x3f00, MCCERR, "mcc3 plane0 error enable 1: & ~set & ~force_off"),
	W32(MCC3, 0x22008, 0, MCCERR, "mcc3 plane0 error status 1 <- 0"),
	OP(CLR32, MCC3, 0x21010, 0x10001, MCCERR, "mcc3 plane0 error enable 2: & ~set & ~force_off"),
	W32(MCC3, 0x22010, 0, MCCERR, "mcc3 plane0 error status 2 <- 0"),
	OP(CLR32, MCC3, 0x61000, 0xb7bffdff, MCCERR, "mcc3 plane1 error enable 0: & ~set & ~force_off"),
	W32(MCC3, 0x62000, 0, MCCERR, "mcc3 plane1 error status 0 <- 0"),
	OP(CLR32, MCC3, 0x61008, 0x3f00, MCCERR, "mcc3 plane1 error enable 1: & ~set & ~force_off"),
	W32(MCC3, 0x62008, 0, MCCERR, "mcc3 plane1 error status 1 <- 0"),
	OP(CLR32, MCC3, 0x61010, 0x10001, MCCERR, "mcc3 plane1 error enable 2: & ~set & ~force_off"),
	W32(MCC3, 0x62010, 0, MCCERR, "mcc3 plane1 error status 2 <- 0"),
	OP(CLR32, MCC3, 0xa1000, 0xb7bffdff, MCCERR, "mcc3 plane2 error enable 0: & ~set & ~force_off"),
	W32(MCC3, 0xa2000, 0, MCCERR, "mcc3 plane2 error status 0 <- 0"),
	OP(CLR32, MCC3, 0xa1008, 0x3f00, MCCERR, "mcc3 plane2 error enable 1: & ~set & ~force_off"),
	W32(MCC3, 0xa2008, 0, MCCERR, "mcc3 plane2 error status 1 <- 0"),
	OP(CLR32, MCC3, 0xa1010, 0x10001, MCCERR, "mcc3 plane2 error enable 2: & ~set & ~force_off"),
	W32(MCC3, 0xa2010, 0, MCCERR, "mcc3 plane2 error status 2 <- 0"),
	OP(CLR32, MCC3, 0xe1000, 0xb7bffdff, MCCERR, "mcc3 plane3 error enable 0: & ~set & ~force_off"),
	W32(MCC3, 0xe2000, 0, MCCERR, "mcc3 plane3 error status 0 <- 0"),
	OP(CLR32, MCC3, 0xe1008, 0x3f00, MCCERR, "mcc3 plane3 error enable 1: & ~set & ~force_off"),
	W32(MCC3, 0xe2008, 0, MCCERR, "mcc3 plane3 error status 1 <- 0"),
	OP(CLR32, MCC3, 0xe1010, 0x10001, MCCERR, "mcc3 plane3 error enable 2: & ~set & ~force_off"),
	W32(MCC3, 0xe2010, 0, MCCERR, "mcc3 plane3 error status 2 <- 0"),
	OP(CLR32, MCC3, 0x155000, 0xfffffff, MCCERR, "mcc3 non-plane error enable 0: & ~set & ~force_off"),
	W32(MCC3, 0x156000, 0, MCCERR, "mcc3 non-plane error status 0 <- 0"),
	OP(CLR32, MCC3, 0x155008, 0xff0f0f, MCCERR, "mcc3 non-plane error enable 1: & ~set & ~force_off"),
	W32(MCC3, 0x156008, 0, MCCERR, "mcc3 non-plane error status 1 <- 0"),
	OP(CLR32, MCC3, 0x155010, 0xffffffff, MCCERR, "mcc3 non-plane error enable 2: & ~set & ~force_off"),
	W32(MCC3, 0x156010, 0, MCCERR, "mcc3 non-plane error status 2 <- 0"),
	/* Not macOS's quiesce: words macOS has 0 at its edge and Linux 0x100 (pd406/407) */
	W32(MCC0, 0x2100c, 0, MCCERR_C, "mcc0 plane0 +0x2100c <- 0 (macOS edge state)"),
	W32(MCC0, 0x2200c, 0, MCCERR_C, "mcc0 plane0 +0x2200c <- 0 (macOS edge state)"),
	W32(MCC0, 0x6100c, 0, MCCERR_C, "mcc0 plane1 +0x2100c <- 0 (macOS edge state)"),
	W32(MCC0, 0x6200c, 0, MCCERR_C, "mcc0 plane1 +0x2200c <- 0 (macOS edge state)"),
	W32(MCC0, 0xa100c, 0, MCCERR_C, "mcc0 plane2 +0x2100c <- 0 (macOS edge state)"),
	W32(MCC0, 0xa200c, 0, MCCERR_C, "mcc0 plane2 +0x2200c <- 0 (macOS edge state)"),
	W32(MCC0, 0xe100c, 0, MCCERR_C, "mcc0 plane3 +0x2100c <- 0 (macOS edge state)"),
	W32(MCC0, 0xe200c, 0, MCCERR_C, "mcc0 plane3 +0x2200c <- 0 (macOS edge state)"),
	W32(MCC1, 0x2100c, 0, MCCERR_C, "mcc1 plane0 +0x2100c <- 0 (macOS edge state)"),
	W32(MCC1, 0x2200c, 0, MCCERR_C, "mcc1 plane0 +0x2200c <- 0 (macOS edge state)"),
	W32(MCC1, 0x6100c, 0, MCCERR_C, "mcc1 plane1 +0x2100c <- 0 (macOS edge state)"),
	W32(MCC1, 0x6200c, 0, MCCERR_C, "mcc1 plane1 +0x2200c <- 0 (macOS edge state)"),
	W32(MCC1, 0xa100c, 0, MCCERR_C, "mcc1 plane2 +0x2100c <- 0 (macOS edge state)"),
	W32(MCC1, 0xa200c, 0, MCCERR_C, "mcc1 plane2 +0x2200c <- 0 (macOS edge state)"),
	W32(MCC1, 0xe100c, 0, MCCERR_C, "mcc1 plane3 +0x2100c <- 0 (macOS edge state)"),
	W32(MCC1, 0xe200c, 0, MCCERR_C, "mcc1 plane3 +0x2200c <- 0 (macOS edge state)"),
	W32(MCC2, 0x2100c, 0, MCCERR_C, "mcc2 plane0 +0x2100c <- 0 (macOS edge state)"),
	W32(MCC2, 0x2200c, 0, MCCERR_C, "mcc2 plane0 +0x2200c <- 0 (macOS edge state)"),
	W32(MCC2, 0x6100c, 0, MCCERR_C, "mcc2 plane1 +0x2100c <- 0 (macOS edge state)"),
	W32(MCC2, 0x6200c, 0, MCCERR_C, "mcc2 plane1 +0x2200c <- 0 (macOS edge state)"),
	W32(MCC2, 0xa100c, 0, MCCERR_C, "mcc2 plane2 +0x2100c <- 0 (macOS edge state)"),
	W32(MCC2, 0xa200c, 0, MCCERR_C, "mcc2 plane2 +0x2200c <- 0 (macOS edge state)"),
	W32(MCC2, 0xe100c, 0, MCCERR_C, "mcc2 plane3 +0x2100c <- 0 (macOS edge state)"),
	W32(MCC2, 0xe200c, 0, MCCERR_C, "mcc2 plane3 +0x2200c <- 0 (macOS edge state)"),
	W32(MCC3, 0x2100c, 0, MCCERR_C, "mcc3 plane0 +0x2100c <- 0 (macOS edge state)"),
	W32(MCC3, 0x2200c, 0, MCCERR_C, "mcc3 plane0 +0x2200c <- 0 (macOS edge state)"),
	W32(MCC3, 0x6100c, 0, MCCERR_C, "mcc3 plane1 +0x2100c <- 0 (macOS edge state)"),
	W32(MCC3, 0x6200c, 0, MCCERR_C, "mcc3 plane1 +0x2200c <- 0 (macOS edge state)"),
	W32(MCC3, 0xa100c, 0, MCCERR_C, "mcc3 plane2 +0x2100c <- 0 (macOS edge state)"),
	W32(MCC3, 0xa200c, 0, MCCERR_C, "mcc3 plane2 +0x2200c <- 0 (macOS edge state)"),
	W32(MCC3, 0xe100c, 0, MCCERR_C, "mcc3 plane3 +0x2100c <- 0 (macOS edge state)"),
	W32(MCC3, 0xe200c, 0, MCCERR_C, "mcc3 plane3 +0x2200c <- 0 (macOS edge state)"),
	/*
	 * note 32 F4: macOS's DCS dynamic power-gate mode. aurora's T6041 (t6041_mcc_macos, at its
	 * commit after the parked CPUs stop and the MCC cache flush) sets +0x20 |= 0x1100 on every
	 * DCS block: AppleT6041MemCacheController's mccSelectDCSDynamicPowerGateMode(1), from the
	 * SoC tuner at boot (ADT mcc-power-gating = 1). On t6020 the blocks are mcc[n] + 0x200000 +
	 * 0x200000 c (the census, pd462/463: no faults) and the edges differ only at +0x1c bit 12
	 * (macOS 0x70a1100, Linux 0x70a0100) and +0x18 (macOS 0x1, Linux 0x3); +0x1c bit 8 is set
	 * in both, so T6041's +0x20 is t6020's +0x1c [inferred]. Here at the same point as aurora's,
	 * after the MCC quiesce and before the clusters.
	 */
	T6020_DCSPG(0, 0), T6020_DCSPG(0, 1), T6020_DCSPG(0, 2), T6020_DCSPG(0, 3),
	T6020_DCSPG(1, 0), T6020_DCSPG(1, 1), T6020_DCSPG(1, 2), T6020_DCSPG(1, 3),
	T6020_DCSPG(2, 0), T6020_DCSPG(2, 1), T6020_DCSPG(2, 2), T6020_DCSPG(2, 3),
	T6020_DCSPG(3, 0), T6020_DCSPG(3, 1), T6020_DCSPG(3, 2), T6020_DCSPG(3, 3),
	W32(PMGR, 0x60000, 0, PERF, "n24 #20 C4 perf-regs pmgr[0]+0x60000"),
	W32(PMGR, 0x68000, 0, PERF, "n24 #20 C4 perf-regs pmgr[0]+0x68000"),
	W32(PMGR, 0x68800, 0, PERF, "n24 #20 C4 perf-regs pmgr[0]+0x68800"),
	W32(PMGR, 0x69000, 0, PERF, "n24 #20 C4 perf-regs pmgr[0]+0x69000"),
	W32(PMGR, 0x69800, 0, PERF, "n24 #20 C4 perf-regs pmgr[0]+0x69800"),
	W32(PMGR, 0x6a000, 0, PERF, "n24 #20 C4 perf-regs pmgr[0]+0x6a000"),
	W32(CLK, 0x70000, 0, PERF, "n24 #20 C4 perf-regs pmgr[4]+0x70000"),
	/*
	 * pd707/708 census dump: macOS has word +0 = 1 in each perf-regs[8] entry (pmgr[2]+0x2c100..
	 * +0x2c690, 0x10 apart: AFNC2 idx 58 at +0x2c3a0, ANS2, APCIE, DISP0, SEP...) with a running
	 * word at +8; Linux has them all 0. Set them, edge_on bit 7, before C4.
	 */
	OP(EDGE_SET32, SOC, 0x2c100, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x100 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c110, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x110 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c120, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x120 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c130, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x130 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c140, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x140 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c150, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x150 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c160, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x160 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c170, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x170 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c180, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x180 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c190, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x190 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c1a0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x1a0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c1b0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x1b0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c1c0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x1c0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c1d0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x1d0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c1e0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x1e0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c1f0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x1f0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c200, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x200 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c210, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x210 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c220, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x220 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c230, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x230 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c240, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x240 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c250, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x250 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c260, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x260 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c270, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x270 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c280, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x280 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c290, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x290 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c2a0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x2a0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c2b0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x2b0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c2c0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x2c0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c2d0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x2d0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c2e0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x2e0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c2f0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x2f0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c300, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x300 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c310, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x310 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c320, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x320 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c330, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x330 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c340, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x340 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c350, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x350 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c360, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x360 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c370, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x370 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c380, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x380 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c390, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x390 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c3a0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x3a0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c3b0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x3b0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c3c0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x3c0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c3d0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x3d0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c3e0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x3e0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c3f0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x3f0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c400, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x400 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c410, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x410 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c420, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x420 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c430, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x430 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c440, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x440 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c450, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x450 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c460, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x460 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c470, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x470 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c480, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x480 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c490, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x490 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c4a0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x4a0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c4b0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x4b0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c4c0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x4c0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c4d0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x4d0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c4e0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x4e0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c4f0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x4f0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c500, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x500 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c510, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x510 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c520, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x520 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c530, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x530 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c540, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x540 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c550, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x550 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c560, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x560 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c570, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x570 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c580, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x580 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c590, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x590 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c5a0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x5a0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c5b0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x5b0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c5c0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x5c0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c5d0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x5d0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c5e0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x5e0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c5f0, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x5f0 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c600, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x600 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c610, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x610 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c620, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x620 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c630, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x630 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c640, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x640 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c650, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x650 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c660, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x660 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c670, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x670 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c680, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x680 enable (macOS 1)"),
	OP(EDGE_SET32, SOC, 0x2c690, SEQ_PS_EDGE_VAL(7, 1, 0), ALL, "EDGEON perf-regs[8] +0x690 enable (macOS 1)"),
	W32(SOC, 0x2c000, 0, PERF, "n24 #20 C4 perf-regs pmgr[2]+0x2c000"),
	W32(AFR, 0x10000, 0, PERF, "n24 #20 C4 perf-regs pmgr[44]+0x10000"),
	W32(PMGR, 0x60000, 0, PERF, "n24 #20 C4 perf-regs pmgr[0]+0x60000 again"),
	W32(SOC, 0x22000, 0, PERF, "n24 #20 C4 perf-regs pmgr[2]+0x22000"),
	T6020_CLUSTER(E, 0xc00102, "E"),
	W64(PMS, T6020_PMP_REPORT, 0x200, CLUSTER, "n24 #22 C5' PMP report: PACC0 withdrawn"),
	T6020_CLUSTER(P0, 0xc00101, "P0"),
	W64(PMS, T6020_PMP_REPORT, 0, CLUSTER, "n24 #22 C5' PMP report: PACC1 withdrawn"),
	T6020_CLUSTER(P1, 0xc00101, "P1"),
	W64(DVFS_E, T6020_DVFS_CMD, 0xc00102, CLUSTER, "n24 #21 C5'' E DVFS CMD again"),
	OP(WAITCLR32, DVFS_E, T6020_DVFS_CMD, 0x80000000, APSCWAIT, "C5'' E DVFS CMD pending clear after"),
	W64(DVFS_P0, T6020_DVFS_CMD, 0xc00101, CLUSTER, "n24 #21 C5'' P0 DVFS CMD again"),
	OP(WAITCLR32, DVFS_P0, T6020_DVFS_CMD, 0x80000000, APSCWAIT, "C5'' P0 DVFS CMD pending clear after"),
	W32(SOC, 0x30000, 0, MISC, "n24 #23 C6 pmgr[2]+0x30000"),
	W32(PMGR, 0x4c200, 0, MISC, "n24 #23 C7 pmgr[0]+0x4c200"),
	W32(PMGR, 0x4c400, 0, MISC, "n24 #23 C7 pmgr[0]+0x4c400"),
	W32(PMGR, 0x4c600, 0, MISC, "n24 #23 C7 pmgr[0]+0x4c600"),
	W32(PMGR, 0x4c000, 0, MISC, "n24 #23 C7 pmgr[0]+0x4c000"),
	/*
	 * C8 is macOS's AppleT6020PMGR::_setFABPerfState (+0) and _setDCSPerfState (+0x400): the
	 * low nibble read-modify-written, then waitReg32(map 0x40 = pmgr reg[40], off, 0x80000000,
	 * 0, 192000), bit 31 busy. pd427: Linux's edge 0x80000333/0x80000555, macOS's 0x333/0x555.
	 * PERFWAIT waits as macOS does, before and after each write; saved[] has the last read.
	 */
	OP(WAITCLR32, PMGR40, 0x0, 0x80000000, PERFWAIT, "C8 FAB perf idle before"),
	OP(WAITCLR32, PMGR40, 0x400, 0x80000000, PERFWAIT, "C8 DCS perf idle before"),
	W32(PMGR40, 0x0, 0x335, MISC, "n24 #23 C8 pmgr[40]+0"),
	OP(WAITCLR32, PMGR40, 0x0, 0x80000000, PERFWAIT, "C8 FAB perf idle (_setFABPerfState's wait)"),
	W32(PMGR40, 0x400, 0x557, MISC, "n24 #23 C8 pmgr[40]+0x400"),
	OP(WAITCLR32, PMGR40, 0x400, 0x80000000, PERFWAIT, "C8 DCS perf idle (_setDCSPerfState's wait)"),
	W32(PMGR40, 0x0, 0x553, MISC, "n24 #23 C8 pmgr[40]+0 again"),
	OP(WAITCLR32, PMGR40, 0x0, 0x80000000, PERFWAIT, "C8 FAB perf idle again"),
	W32(PMGR40, 0x400, 0x775, MISC, "n24 #23 C8 pmgr[40]+0x400 again"),
	OP(WAITCLR32, PMGR40, 0x400, 0x80000000, PERFWAIT, "C8 DCS perf idle again"),
	W32(AFR, T6020_PS_AFR, 0, AFR, "n24 #24 C9 AFR PS"),
	/*
	 * AppleT6020PMGR::quiesceHW, per die unless MiniPMGR +0x4d010 has bits 18-19 set:
	 * writeReg32(map 6 = pmgr reg[44], 0x100, 0), then waitReg32(map 6, 0x100, 0xf0, 0, 192000),
	 * which panics on a timeout. macOS's next write comes 10 µs later; Linux's next PMGR access
	 * stalls ~20 ms after AFR's write (13 of 13 wlog runs). Its map 3 +0x288/+0x290 is t6022's.
	 */
	OP(WAITCLR32, AFR, T6020_PS_AFR, PS_ACTUAL, AFRWAIT, "C9 AFR actual 0 (quiesceHW's waitReg32)"),
	/* The waits are macOS's gaps (N24-E); what it polls there is unknown. */
	/*
	 * pd413: the PMGR interrupt status 0x80003513 doesn't clear on read. ADT pmgr
	 * interrupt-config: 1 PACC0_PWRUP, 2 PACC1_PWRUP, 3 ANE_PWRUP, 4 AVEMSR_PWRUP, 6 DVMF_COP
	 * (AIC 312, 313, 314, 317, 446 by order). macOS acks a cluster's power-up event with
	 * ApplePMGR::clearClusterInterruptStatus: its cluster-ctl word |= 0x20 (13.7.8 static: reg
	 * group 2 = cluster-ctl-offset). Linux never acks the ones latched since boot. DVMF_COP's
	 * clear is not known.
	 */
	OP(SET32, PMGR, T6020_CLUSTER_CTL + 0x4, 0x20, PMGRACK, "PACC0_PWRUP ack: cluster-ctl PACC0 |= 0x20"),
	OP(SET32, PMGR, T6020_CLUSTER_CTL + 0x8, 0x20, PMGRACK, "PACC1_PWRUP ack: cluster-ctl PACC1 |= 0x20"),
	OP(SET32, PMGR, T6020_CLUSTER_CTL + 0xc, 0x20, PMGRACK, "ANE_PWRUP ack: cluster-ctl ANE0 |= 0x20"),
	OP(SET32, PMGR, T6020_CLUSTER_CTL + 0x18, 0x20, PMGRACK, "AVEMSR_PWRUP ack: cluster-ctl AVEMSR |= 0x20"),
	OP(R32, CLK, 0x79004, 0, PMGRACK, "PMGR interrupt status after the acks"),
	/*
	 * DVMF_COP (id 6, AIC 446): AppleT6020PMGR::handleInterruptWithID reads readReg32(map 0x44,
	 * +4, die) = pmgr reg[47] 0x28e079004 per die; with bit 31 set it writes the word back
	 * | 0x80000000 and panics ("DVMFCop"). macOS has the word 0 at its edge (pd406); Linux has
	 * 0x80003513 from boot (pd407-414), which nothing clears. The same write-back, no panic.
	 */
	OP(SET32, CLK, 0x79004, 0x80000000, DVMFACK, "DVMF_COP ack: PMGR status |= bit 31 (write back)"),
	OP(R32, CLK, 0x79004, 0, DVMFACK, "PMGR interrupt status after the DVMF_COP ack"),
	/*
	 * Note 32 §3: the PS census at the edge, macOS 4 of 4 (pd384, 402, 404, 406), Linux 8 of 8.
	 * macOS writes none of these in its entry (0 writes in pd212, pd252, pd402): its values are
	 * the hardware's automatic state, so there is no macOS order to copy. ST_SYS is raised
	 * before the other two are gated. Each waits PS_POLL_US for its actual state and goes on.
	 * - APCIEEDGE: APCIE_ST_SYS on (macOS 0x1f0003ff, Linux 0x1000030f actual 0): target f,
	 *   AUTO off, as T6040's form (with AUTO on Linux's idle lane gates it again);
	 *   APCIE_PHY_SW (macOS 0x1400024f, Linux 0x1f0000ff) and APCIE_GP_SYS (macOS 0x1404024f,
	 *   PS_MIN 4) clock-gated: target 4, AUTO off, as T6040's 0x0f000244.
	 * - MTPAUTO: Linux has the six words 0xf0000ff (AUTO off, on); macOS AUTO with target f,
	 *   actual 4 (base, scm_fabric, spi0, sram: 0x1400024f) or 0 (cpu, fabric: 0x1000030f).
	 *   Children first by the ADT's parents (sram <- scm_fabric, cpu; all <- fabric).
	 */
	OP(PS_SET, SOC, T6020_PS_APCIE_ST_SYS, SEQ_PS_SET_VAL(PS_ON, 0xf), APCIEEDGE,
	   "APCIE_ST_SYS on, AUTO off (macOS edge 0x1f0003ff)"),
	OP(PS_SET, SOC, T6020_PS_APCIE_PHY_SW, SEQ_PS_SET_VAL(0x4, 0x4), APCIEEDGE,
	   "APCIE_PHY_SW clock-gated (macOS edge 0x1400024f)"),
	OP(PS_SET, SOC, T6020_PS_APCIE_GP_SYS, SEQ_PS_SET_VAL(0x40004, 0x4), APCIEEDGE,
	   "APCIE_GP_SYS clock-gated, PS_MIN 4 (macOS edge 0x1404024f)"),
	OP(PS_SET, AON, T6020_PS_MTP_SRAM, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x4), MTPAUTO,
	   "mtp_sram AUTO (macOS edge 0x1400024f)"),
	OP(PS_SET, AON, T6020_PS_MTP_SCM_FABRIC, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x4), MTPAUTO,
	   "mtp_scm_fabric AUTO (macOS edge 0x1400024f)"),
	OP(PS_SET, AON, T6020_PS_MTP_SPI0, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x4), MTPAUTO,
	   "mtp_spi0 AUTO (macOS edge 0x1400024f)"),
	OP(PS_SET, AON, T6020_PS_MTP_CPU, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x0), MTPAUTO,
	   "mtp_cpu AUTO (macOS edge 0x1000030f)"),
	OP(PS_SET, AON, T6020_PS_MTP_BASE, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x4), MTPAUTO,
	   "mtp_base AUTO (macOS edge 0x1400024f)"),
	OP(PS_SET, AON, T6020_PS_MTP_FABRIC, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x0), MTPAUTO,
	   "mtp_fabric AUTO (macOS edge 0x1000030f)"),
	/*
	 * AFNCAUTO (note 38, DISPLAY candidate 1): the display islands' fabric parents, by the
	 * j416s ADT DISP0_SYS <- AFNC2_LW0 <- AFNC2_LS <- AFNC2_IOA (AFNC2_LW1: SIO, ISP_SYS) and
	 * DISPEXT1_SYS <- AFNC1_LW2. Edge census pd384/406 (macOS) vs pd385/407 (Linux): macOS
	 * 0x1000030f (afnc1_lw2 0x1000020f): auto state 0, actual 0; Linux 0x1f0000ff: auto f,
	 * actual f. The settable bits (AUTO_ENABLE, PS_MIN 0, target f) are already the same in
	 * both: bits 27:24 are read-only, so this re-asserts AUTO and waits for actual 0, a miss
	 * counted. With DISP the DCP words below them are off first. afnc0_lw0 (DISPEXT0_SYS's
	 * parent) is left alone: macOS keeps it on (0x1f0003ff, PMS_BRIDGE). Children first.
	 */
	OP(PS_SET, SOC, T6020_PS_AFNC2_LW0, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x0), AFNCAUTO,
	   "afnc2_lw0 AUTO, actual 0 (macOS edge 0x1000030f)"),
	OP(PS_SET, SOC, T6020_PS_AFNC2_LW1, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x0), AFNCAUTO,
	   "afnc2_lw1 AUTO, actual 0 (macOS edge 0x1000030f)"),
	OP(PS_SET, SOC, T6020_PS_AFNC2_LS, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x0), AFNCAUTO,
	   "afnc2_ls AUTO, actual 0 (macOS edge 0x1000030f)"),
	OP(PS_SET, SOC, T6020_PS_AFNC2_IOA, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x0), AFNCAUTO,
	   "afnc2_ioa AUTO, actual 0 (macOS edge 0x1000030f)"),
	OP(PS_SET, PMGR, T6020_PS_AFNC1_LW2, SEQ_PS_SET_VAL(PS_AUTO_ENABLE | PS_ON, 0x0), AFNCAUTO,
	   "afnc1_lw2 AUTO, actual 0 (macOS edge 0x1000020f)"),
	/*
	 * PLLEARLY (note 44): at the DISPLAY write the reg[46] status word +8 reads 0x21 in macOS
	 * (pd532) and 0xb802 in Linux (11 of 11 snapshots), iBoot's value (arm 0xb802, 6 of 6);
	 * after setPLLOffMode both read 0x31. AppleT6020PMGR::setPLLOffMode(map 0x37 = reg[46], 0,
	 * mode 3) as 13.7.8 has it: +0 <- (old & ~0x38) | 3 << 3, then old | 2, then old & ~1, then
	 * wait for bit 31 (busy) to clear. macOS does it after the clusters; this does it before.
	 */
	OP(SET32, CLK, 0x44000, 0x8000, CLK15, "CLK15 pmgr[4]+0x44000 |= bit 15 (macOS 0x80008000 at the DISPLAY write)"),
	OP(SET32, CLK, 0x48000, 0x8000, CLK15, "CLK15 pmgr[4]+0x48000 |= bit 15 (macOS 0x80008000 at the DISPLAY write)"),
	/*
	 * NCORUN (note 45): pmgr[4]+0x3c000..0x4c000 is /arm-io/nco, five channels 16 KB apart
	 * (clk-apple-nco: +0 CTRL, +4 DIV, +8 INC1, +0xc INC2, +0x10 ACCINIT). At the DISPLAY write
	 * macOS reads ch1-3 CTRL 0x80008000, Linux ch1 0x80008000 and ch2/3 0x80000000; pd548: bit
	 * 15 is status. 13.7.8's AppleS5L8960XNCO::_setNCOFrequency: CTRL <- 0, DIV, INC1, INC2,
	 * ACCINIT, then CTRL <- 0x80001000; _writeNCOReg waits for CTRL bit 30 clear before every
	 * write but the enabling one. Values: 12.288 MHz from a 1068 MHz reference, Linux's
	 * arithmetic (ch2 is mca2's MCLK, ADT NCOf 2; macOS's rate and t6020's reference unread).
	 * ch1, which iBoot leaves running, is read for its values.
	 */
	OP(R32, CLK, 0x40000, 0, NCORUN, "NCORUN ch1 CTRL"),
	OP(R32, CLK, 0x40004, 0, NCORUN, "NCORUN ch1 DIV"),
	OP(R32, CLK, 0x40008, 0, NCORUN, "NCORUN ch1 INC1"),
	OP(R32, CLK, 0x4000c, 0, NCORUN, "NCORUN ch1 INC2"),
	OP(R32, CLK, 0x40010, 0, NCORUN, "NCORUN ch1 ACCINIT"),
	OP(R32, CLK, 0x44004, 0, NCORUN, "NCORUN ch2 DIV before"),
	OP(R32, CLK, 0x48004, 0, NCORUN, "NCORUN ch3 DIV before"),
	W32(CLK, 0x44000, 0, NCORUN, "NCORUN ch2 CTRL <- 0"),
	OP(WAITCLR32, CLK, 0x44000, 0x40000000, NCORUN, "NCORUN ch2 CTRL bit 30 clear"),
	W32(CLK, 0x44004, 0xe51, NCORUN, "NCORUN ch2 DIV"),
	W32(CLK, 0x44008, 0x9b4600, NCORUN, "NCORUN ch2 INC1"),
	W32(CLK, 0x4400c, 0xffdfc600, NCORUN, "NCORUN ch2 INC2"),
	W32(CLK, 0x44010, 0x80000000, NCORUN, "NCORUN ch2 ACCINIT"),
	W32(CLK, 0x44000, 0x80001000, NCORUN, "NCORUN ch2 CTRL <- 0x80001000 (_setNCOFrequency)"),
	W32(CLK, 0x48000, 0, NCORUN, "NCORUN ch3 CTRL <- 0"),
	OP(WAITCLR32, CLK, 0x48000, 0x40000000, NCORUN, "NCORUN ch3 CTRL bit 30 clear"),
	W32(CLK, 0x48004, 0xe51, NCORUN, "NCORUN ch3 DIV"),
	W32(CLK, 0x48008, 0x9b4600, NCORUN, "NCORUN ch3 INC1"),
	W32(CLK, 0x4800c, 0xffdfc600, NCORUN, "NCORUN ch3 INC2"),
	W32(CLK, 0x48010, 0x80000000, NCORUN, "NCORUN ch3 ACCINIT"),
	W32(CLK, 0x48000, 0x80001000, NCORUN, "NCORUN ch3 CTRL <- 0x80001000 (_setNCOFrequency)"),
	OP(R32, CLK, 0x44000, 0, NCORUN, "NCORUN ch2 CTRL after (macOS 0x80008000)"),
	OP(R32, CLK, 0x48000, 0, NCORUN, "NCORUN ch3 CTRL after (macOS 0x80008000)"),
	OP(R32, PLL, 0x8, 0, PLLEARLY, "PLLEARLY PLL +8 before"),
	W32(PLL, 0x0, 0x219, PLLEARLY, "PLLEARLY setPLLOffMode +0 <- mode 3"),
	OP(SET32, PLL, 0x0, 0x2, PLLEARLY, "PLLEARLY setPLLOffMode +0 |= 2"),
	OP(CLR32, PLL, 0x0, 0x1, PLLEARLY, "PLLEARLY setPLLOffMode +0 &= ~1"),
	OP(WAITCLR32, PLL, 0x0, 0x80000000, PLLEARLY, "PLLEARLY setPLLOffMode busy clear"),
	OP(R32, PLL, 0x8, 0, PLLEARLY, "PLLEARLY PLL +8 after"),
	/*
	 * CLACK: after each write enableCluster's ack, bit 4 clear (note 33 C11). DISPLAY was 0x2f
	 * before its 0x20 (pd427's plan): target 0, bit 5 acked; the PMGR sets bit 4 for the
	 * off-request, and pd427 (1 of 1) still read 0x10 at the edge, where macOS reads 0.
	 */
	OP(CLR32, PMGR, T6020_CLUSTER_CTL + 0x0, 0xf, CLRMW, "C10 cluster-ctl EACC <- old & ~0xf (enableCluster)"),
	W32(PMGR, T6020_CLUSTER_CTL + 0x0, 0, CLCTL, "n24 #25 C10 cluster-ctl EACC"),
	DELAY(2200, CLCTL, "n24 #25 C10 after EACC"),
	CLACK(0x0, 0, "EACC"),
	OP(CLR32, PMGR, T6020_CLUSTER_CTL + 0x4, 0xf, CLRMW, "C10 cluster-ctl PACC0 <- old & ~0xf (enableCluster)"),
	W32(PMGR, T6020_CLUSTER_CTL + 0x4, 0, CLCTL, "n24 #25 C10 cluster-ctl PACC0"),
	DELAY(1500, CLCTL, "n24 #25 C10 after PACC0"),
	CLACK(0x4, 0, "PACC0"),
	OP(CLR32, PMGR, T6020_CLUSTER_CTL + 0x8, 0xf, CLRMW, "C10 cluster-ctl PACC1 <- old & ~0xf (enableCluster)"),
	W32(PMGR, T6020_CLUSTER_CTL + 0x8, 0, CLCTL, "n24 #25 C10 cluster-ctl PACC1"),
	DELAY(700, CLCTL, "n24 #25 C10 after PACC1"),
	CLACK(0x8, 0, "PACC1"),
	OP(CLR32, PMGR, T6020_CLUSTER_CTL + 0xc, 0xf, CLRMW, "C10 cluster-ctl ANE0 <- old & ~0xf (enableCluster)"),
	W32(PMGR, T6020_CLUSTER_CTL + 0xc, 0, CLCTL, "n24 #25 C10 cluster-ctl ANE0"),
	CLACK(0xc, 0, "ANE0"),
	OP(PS_LOWER, SOC, 0x128, 0, ISPOFF, "ISPOFF ispsens0 PS off (macOS 0x4000200 at the DISPLAY write)"),
	OP(PS_LOWER, SOC, 0x130, 0, ISPOFF, "ISPOFF ispsens1 PS off (macOS 0x4000200 at the DISPLAY write)"),
	OP(PS_LOWER, SOC, 0x138, 0, ISPOFF, "ISPOFF ispsens2 PS off (macOS 0x4000200 at the DISPLAY write)"),
	OP(PS_LOWER, SOC, 0x140, 0, ISPOFF, "ISPOFF ispsens3 PS off (macOS 0x4000200 at the DISPLAY write)"),
	W32(PMGR, 0x4c400, 0, AVEOFF, "AVEOFF pmgr[0]+0x4c400 <- 0 before AVEMSR, moved before DISPLAY"),
	OP(CLR32, PMGR, T6020_CLUSTER_CTL + 0x18, 0xf, AVEOFF, "AVEOFF cluster-ctl AVEMSR <- old & ~0xf before DISPLAY (macOS has it off there)"),
	CLACK(0x18, 0, "AVEMSR (AVEOFF)"),
	W32(PMGR, T6020_CLUSTER_CTL + 0x10, 0x20, CLCTL, "n24 #25 C10 cluster-ctl DISPLAY"),
	CLACK(0x10, SEQ_CLACK_ZERO, "DISPLAY, then 0 as at macOS's edge"),
	W32(PMGR, 0x4c400, 0, CLCTL, "n24 #25 C10 pmgr[0]+0x4c400 before AVEMSR"),
	OP(CLR32, PMGR, T6020_CLUSTER_CTL + 0x18, 0xf, CLRMW, "C10 cluster-ctl AVEMSR <- old & ~0xf (enableCluster)"),
	W32(PMGR, T6020_CLUSTER_CTL + 0x18, 0, CLCTL, "n24 #25 C10 cluster-ctl AVEMSR"),
	CLACK(0x18, 0, "AVEMSR"),
	/* pd427: DISPLAY reads 0x10 at Linux's edge, 0 at macOS's (which wrote 0x20 here too) */
	W32(PMGR, T6020_CLUSTER_CTL + 0x10, 0, DISPCTL, "DISPLAY cluster-ctl <- 0 (macOS edge)"),
	OP(R32, PMGR, T6020_CLUSTER_CTL + 0x10, 0, DISPCTL, "DISPLAY cluster-ctl after"),
	OP(PS_NO_AUTO, SOC, T6020_PS_SIO, 0, SIO, "n24 #26 C11 SIO PS"),
	DELAY(1600, SIO, "n24 #26 the gap between SIO and SIO_CPU"),
	OP(PS_NO_AUTO, SOC, T6020_PS_SIO_CPU, 0, SIO, "n24 #26 C12 SIO_CPU PS"),
	OP(PS_EDGE, PMGR, 0x120, SEQ_PS_EDGE_VAL(0, PS_ON, 0xf), ALL, "EDGEON GPIO on (macOS 0xff at its commit)"),
	OP(PS_EDGE, SOC, T6020_PS_SIO_CPU, SEQ_PS_EDGE_VAL(1, PS_ON, 0xf), ALL, "EDGEON SIO_CPU on, no AUTO (macOS 0xf0002ff)"),
	OP(PS_EDGE, PMGR, 0x118, SEQ_PS_EDGE_VAL(2, PS_AUTO_ENABLE | PS_MIN | PS_ON, 0xf), ALL, "EDGEON PMS PS_MIN f (macOS 0x1f0f00ff)"),
	OP(PS_EDGE, AON, 0xc0, SEQ_PS_EDGE_VAL(2, PS_AUTO_ENABLE | PS_MIN | PS_ON, 0xf), ALL, "EDGEON DEBUG_SWITCH PS_MIN f (macOS 0x1f0f00ff)"),
	OP(PS_EDGE, SOC, 0x4010, SEQ_PS_EDGE_VAL(3, 0, 0), ALL, "EDGEON dprx off under SIO (macOS off at the edge, Linux 0x244, pd384/385)"),
	OP(PS_EDGE, SOC, 0x228, SEQ_PS_EDGE_VAL(3, 0, 0), ALL, "EDGEON i2c5 off under SIO (macOS off at the edge, Linux 0x244, pd384/385)"),
	OP(PS_EDGE, SOC, 0x230, SEQ_PS_EDGE_VAL(3, 0, 0), ALL, "EDGEON i2c6 off under SIO (macOS off at the edge, Linux 0x244, pd384/385)"),
	OP(PS_EDGE, SOC, 0x238, SEQ_PS_EDGE_VAL(3, 0, 0), ALL, "EDGEON i2c7 off under SIO (macOS off at the edge, Linux 0x244, pd384/385)"),
	OP(PS_EDGE, SOC, 0x1f0, SEQ_PS_EDGE_VAL(3, 0, 0), ALL, "EDGEON fpwm1 off under SIO (macOS off at the edge, Linux 0x244, pd384/385)"),
	OP(PS_EDGE, SOC, 0x1f8, SEQ_PS_EDGE_VAL(3, 0, 0), ALL, "EDGEON fpwm2 off under SIO (macOS off at the edge, Linux 0x244, pd384/385)"),
	OP(PS_EDGE, SOC, 0x250, SEQ_PS_EDGE_VAL(3, 0, 0), ALL, "EDGEON sio_spmi0 off under SIO (macOS off at the edge, Linux 0x244, pd384/385)"),
	OP(PS_EDGE, SOC, 0x258, SEQ_PS_EDGE_VAL(3, 0, 0), ALL, "EDGEON sio_spmi1 off under SIO (macOS off at the edge, Linux 0x244, pd384/385)"),
	OP(PS_EDGE, SOC, 0x260, SEQ_PS_EDGE_VAL(3, 0, 0), ALL, "EDGEON sio_spmi2 off under SIO (macOS off at the edge, Linux 0x244, pd384/385)"),
	/*
	 * pd674-702: at macOS's edge AFNC2_IOA/LS/LW1 are auto-gated (0x1000030f) with SIO on; in
	 * Linux they stay on (0x1f0000ff) whatever we sleep. Force them off to see whether the
	 * engine cares: bit 5 SIO_CPU and SIO off first (LW1's children), bit 4 the fabric itself.
	 */
	/*
	 * pd674/675: SIO's children macOS has on at its edge and Linux not: FPWM0 (macOS 0x2ff, Linux
	 * 0x244: target 4), SPI_P, AUDIO_P, UART_N, PMGR_SOC_OCLA (macOS 0xff/0x2ff, Linux 0x200).
	 */
	OP(PS_EDGE, SOC, 0x1e8, SEQ_PS_EDGE_VAL(6, PS_ON, 0xf), ALL, "EDGEON fpwm0 on (macOS 0x2ff)"),
	OP(PS_EDGE, SOC, 0x248, SEQ_PS_EDGE_VAL(6, PS_ON, 0xf), ALL, "EDGEON spi_p on (macOS 0xff)"),
	OP(PS_EDGE, SOC, 0x270, SEQ_PS_EDGE_VAL(6, PS_ON, 0xf), ALL, "EDGEON audio_p on (macOS 0x2ff)"),
	OP(PS_EDGE, SOC, 0x308, SEQ_PS_EDGE_VAL(6, PS_ON, 0xf), ALL, "EDGEON uart_n on (macOS 0xff)"),
	OP(PS_EDGE, PMGR, 0x138, SEQ_PS_EDGE_VAL(6, PS_ON, 0xf), ALL, "EDGEON pmgr_soc_ocla on (macOS 0xff)"),
	/*
	 * pd725 vs pd667 (fresh census, AFNC2 matched in pd723): APCIE's words have AUTO in macOS
	 * (gp_sys 0x1404024f, phy_sw 0x1400024f: auto-gated to 4; st_sys 0x1f0003ff), Linux's
	 * APCIEEDGE leaves them without (0xf040244, 0xf000244, 0xf0003ff); DWI on in macOS (0x2ff,
	 * Linux 0x244); UART1-6 on in macOS, off in Linux. edge_on bit 12.
	 */
	OP(PS_EDGE, SOC, 0x408, SEQ_PS_EDGE_VAL(12, PS_AUTO_ENABLE | PS_ON, 0xf), ALL, "EDGEON apcie_st_sys AUTO, on (macOS 0x1f0003ff)"),
	OP(PS_EDGE, SOC, 0x418, SEQ_PS_EDGE_VAL(12, PS_AUTO_ENABLE | 0x40000 | PS_ON, 0x4), ALL, "EDGEON apcie_gp_sys AUTO, PS_MIN 4 (macOS 0x1404024f)"),
	OP(PS_EDGE, SOC, 0x428, SEQ_PS_EDGE_VAL(12, PS_AUTO_ENABLE | PS_ON, 0x4), ALL, "EDGEON apcie_phy_sw AUTO (macOS 0x1400024f)"),
	OP(PS_EDGE, PMGR, 0x110, SEQ_PS_EDGE_VAL(12, PS_ON, 0xf), ALL, "EDGEON dwi on (macOS 0x2ff)"),
	OP(PS_EDGE, SOC, 0x368, SEQ_PS_EDGE_VAL(12, PS_ON, 0xf), ALL, "EDGEON uart1 on (macOS 0xff)"),
	OP(PS_EDGE, SOC, 0x370, SEQ_PS_EDGE_VAL(12, PS_ON, 0xf), ALL, "EDGEON uart2 on (macOS 0xff)"),
	OP(PS_EDGE, SOC, 0x378, SEQ_PS_EDGE_VAL(12, PS_ON, 0xf), ALL, "EDGEON uart3 on (macOS 0xff)"),
	OP(PS_EDGE, SOC, 0x380, SEQ_PS_EDGE_VAL(12, PS_ON, 0xf), ALL, "EDGEON uart4 on (macOS 0x2ff)"),
	OP(PS_EDGE, SOC, 0x388, SEQ_PS_EDGE_VAL(12, PS_ON, 0xf), ALL, "EDGEON uart5 on (macOS 0x2ff)"),
	OP(PS_EDGE, SOC, 0x390, SEQ_PS_EDGE_VAL(12, PS_ON, 0xf), ALL, "EDGEON uart6 on (macOS 0x2ff)"),
	OP(PS_EDGE, SOC, T6020_PS_SIO_CPU, SEQ_PS_EDGE_VAL(5, 0, 0), ALL, "EDGEON SIO_CPU off (forced, AFNC2 test)"),
	OP(PS_EDGE, SOC, T6020_PS_SIO, SEQ_PS_EDGE_VAL(5, 0, 0), ALL, "EDGEON SIO off (forced, AFNC2 test)"),
	OP(PS_EDGE, SOC, T6020_PS_AFNC2_LW1, SEQ_PS_EDGE_VAL(4, 0, 0), ALL, "EDGEON afnc2_lw1 off (forced; macOS auto-gated 0x1000030f)"),
	OP(PS_EDGE, SOC, T6020_PS_AFNC2_LS, SEQ_PS_EDGE_VAL(4, 0, 0), ALL, "EDGEON afnc2_ls off (forced; macOS auto-gated 0x1000030f)"),
	OP(PS_EDGE, SOC, T6020_PS_AFNC2_IOA, SEQ_PS_EDGE_VAL(4, 0, 0), ALL, "EDGEON afnc2_ioa off (forced; macOS auto-gated 0x1000030f)"),
	/*
	 * SPMIIDLE (note 48): at C14's first write nub_spmi0's PS reads 0x1400024f in macOS (pd577,
	 * gated: its last SPMI traffic, the 0x50, is ~112 ms back) and 0x1f0002ff in Linux (pd578,
	 * active), which gates by itself within the HV's 100 ms hold. Wait here for actual to drop
	 * below 8 (0xf active, 4 gated), so the PMU's bus is idle through C13-C15 as in macOS.
	 * The RTC read for the alarm moves here, before the wait: macOS has no SPMI traffic
	 * between C14 and commit 1 (24 µs apart, note 24), Linux's read sat there.
	 */
	PMU(PMU_RTC_NOW, PMU_RTC_COUNTER, 6, SPMIIDLE, "SPMIIDLE the PMU RTC now, for the alarm, before the bus goes idle"),
	OP(WAITCLR32, AON, T6020_PS_NUB_SPMI0, 0x80, SPMIIDLE, "SPMIIDLE nub_spmi0 PS actual gated (macOS 0x1400024f at C14)"),
	W32(CLK, 0x38160, 0x80100000, CLOCKS, "n24 #27 C13 ClkGen-SOC mux +0x160"),
	W32(CLK, 0x38168, 0x80100000, CLOCKS, "n24 #27 C13 ClkGen-SOC mux +0x168"),
	W32(CLK, 0x38164, 0x80100000, CLOCKS, "n24 #27 C13 ClkGen-SOC mux +0x164"),
	W32(CLK, 0x38158, 0x80100000, CLOCKS, "n24 #27 C13 ClkGen-SOC mux +0x158"),
	W32(CLK, 0x3816c, 0x80100000, CLOCKS, "n24 #27 C13 ClkGen-SOC mux +0x16c"),
	/* Literal values, bit 31 included (N24-F): not a read-modify-write. */
	W32(PLL, 0x0, 0x219, PLL, "n24 #28 C14 PLL off 1"),
	W32(PLL, 0x0, 0x8000021b, PLL, "n24 #28 C14 PLL off 2"),
	W32(PLL, 0x0, 0x8000021a, PLL, "n24 #28 C14 PLL off 3"),
	/*
	 * PLLWAIT (note 48): macOS's setPLLOffMode polls +0 bit 31 after its last write. macOS's
	 * PLL is already off there (+8 0x2021, pd577), Linux's still runs (0xb802, pd578) and
	 * makes the real transition here, which commit 1 doesn't wait for. +8 and +0x800 (0 in
	 * macOS, 3 in Linux with the PLL on, 1 with it off) are read after it.
	 */
	OP(WAITCLR32, PLL, 0x0, 0x80000000, PLLWAIT, "PLLWAIT C14 setPLLOffMode busy clear"),
	OP(R32, PLL, 0x8, 0, PLLWAIT, "PLLWAIT PLL +8 after C14 (macOS edge 0x31/0x2031)"),
	OP(R32, PLL, 0x800, 0, PLLWAIT, "PLLWAIT PLL +0x800 after C14 (macOS 0)"),
	/*
	 * macOS's WD2 at the edge: ctrl 4, the bite 60 s on (measured every edge since pd159). The
	 * write that arms it is unknown (G22, ~7 ms before the edge); these writes are m1n1's order.
	 */
	OP(WD2, AON, 0x44020, 60, WD2, "n24 #19 WD2 60 s, ctrl 4 (G22: writer unknown)"),
	/*
	 * G14: at macOS's edge pmgr[7] +0xc..+0x2c hold these (pd212, pd252, pd203: the same), at
	 * Linux's all 0 (pd342), which leaves every wake source enabled (aurora, T8140). No AP write
	 * puts them there on macOS (0 in every log): one of the co-processors it tells does. Here
	 * the AP writes the values themselves, as a switch.
	 */
	W32(WAKE, 0x0c, 0xf3ffafff, WAKEMASK, "G14 wake mask +0x0c, macOS's edge value"),
	W32(WAKE, 0x10, 0xffa1f6ff, WAKEMASK, "G14 wake mask +0x10, macOS's edge value"),
	W32(WAKE, 0x14, 0xfbdfffff, WAKEMASK, "G14 wake mask +0x14, macOS's edge value"),
	W32(WAKE, 0x18, 0x3fffffff, WAKEMASK, "G14 wake mask +0x18, macOS's edge value"),
	W32(WAKE, 0x1c, 0xffffffc0, WAKEMASK, "G14 wake mask +0x1c, macOS's edge value"),
	W32(WAKE, 0x20, 0xffffffff, WAKEMASK, "G14 wake mask +0x20, macOS's edge value"),
	W32(WAKE, 0x24, 0x7fffffff, WAKEMASK, "G14 wake mask +0x24, macOS's edge value"),
	W32(WAKE, 0x28, 0xffffffff, WAKEMASK, "G14 wake mask +0x28, macOS's edge value"),
	W32(WAKE, 0x2c, 0x0000007f, WAKEMASK, "G14 wake mask +0x2c, macOS's edge value"),
	/* Not macOS's: it knows the time without asking. Read here to keep the commits' gap macOS's. */
	/*
	 * pd406/407: the PMGR interrupt status (clkgen block +0x79004, AIC 312-317/446) reads 0 at
	 * macOS's edge and 0x80003513 at Linux's; macOS writes nothing to 0x28e079xxx, and its
	 * handler (AppleT6020PMGR::handleInterruptWithID) only reads. A read here, after our own
	 * cluster writes: if the status clears on read, the census shows it.
	 */
	OP(R32, CLK, 0x79004, 0, PMGRIRQ, "PMGR interrupt status read (clear-on-read?)"),
	PMU(PMU_RTC_NOW, PMU_RTC_COUNTER, 6, PMU, "Linux: the PMU RTC now, for the alarm"),
	/*
	 * aurora's generic sleep.c (T8140/T6040, measured on macOS): right before the commit, WD0
	 * off, WD2 armed and the AON "AP deadline" aon-misc +0x08 <- 0 (T6040: wdt reg[2]+8).
	 * t6020's aon-misc is 0x29e2a0000 (AON +0x20000). edge_on bit 14.
	 */
	OP(EDGE_W32, AON, 0x20008, SEQ_PS_EDGE_VAL(14, 0, 0), ALL, "EDGEON aon-misc +0x08 AP deadline <- 0 (aurora sleep.c)"),
	/*
	 * aurora sleep.c / sleep-t6040.c (measured on macOS): right after WD2 is armed, the SMC's AP
	 * watchdog deadline (t6020: wdt reg[2] 0x29e2a002c, the word #11/#19 arm) is written 0.
	 * edge_on bit 15; the HV's smcwd hook passes a 0 through as 0.
	 */
	OP(EDGE_W32, AON, 0x2002c, SEQ_PS_EDGE_VAL(15, 0, 0), ALL, "EDGEON SMC deadline <- 0 after WD2 (aurora)"),
	/*
	 * Tanabota note 62 R1: nub-spmi0's peripheral enables +0x20/+0x24 read 0x4 / 0x40000000 in
	 * macOS through its commit (bit 2 the PMU's source: the RTC alarm; bit 62 btm), 0/0 in Linux
	 * (no interrupts in our DT). Clear the latches (+0x60/+0x64, W1C), then enable. edge_on bit 16.
	 */
	OP(R32, NUB_SPMI, 0x60, 0, ALL, "nub-spmi0 latch +0x60 (read)"),
	OP(R32, NUB_SPMI, 0x64, 0, ALL, "nub-spmi0 latch +0x64 (read)"),
	OP(R32, NUB_SPMI, 0x80, 0, ALL, "nub-spmi0 +0x80 (read)"),
	OP(EDGE_W32, NUB_SPMI, 0x60, SEQ_PS_EDGE_VAL(16, 0x4, 0), ALL, "EDGEON nub-spmi0 latch +0x60 <- 0x4 (W1C)"),
	OP(EDGE_W32, NUB_SPMI, 0x64, SEQ_PS_EDGE_VAL(16, 0x40000000, 0), ALL, "EDGEON nub-spmi0 latch +0x64 <- 0x40000000 (W1C)"),
	/*
	 * pd744/745: the one nub-spmi0 word that differs at the edge: +0x40 = 0x2000001 in macOS
	 * (aurora's NOTIFY_ENABLE, written on the PMU's controller on every SoC), 0 in Linux.
	 * Non-posted (pd339). edge_on bit 17.
	 */
	OP(EDGE_W32, NUB_SPMI, 0x40, SEQ_PS_EDGE_VAL(17, 0x2000001, 0), ALL, "EDGEON nub-spmi0 +0x40 NOTIFY_ENABLE <- 0x2000001 (macOS)"),
	OP(EDGE_W32, NUB_SPMI, 0x20, SEQ_PS_EDGE_VAL(16, 0x4, 0), ALL, "EDGEON nub-spmi0 enable +0x20 <- 0x4 (macOS)"),
	OP(EDGE_W32, NUB_SPMI, 0x24, SEQ_PS_EDGE_VAL(16, 0x40000000, 0), ALL, "EDGEON nub-spmi0 enable +0x24 <- 0x40000000 (macOS)"),
	OP(ENTRY2, PMGR, 0, 0, COMMIT, "Linux: hybrid bit 28, the second entry of a boot (note 86 cycle 2): unlatch BUSY words, ANS bridge, crumbs"),
	OP(GATE, PMGR, 0, SEQ_GATE_PMU | SEQ_GATE_RTC, COMMIT, "Linux: no commit 1 on a PMU failure or a bad RTC"),
	W32(COMMIT, 0x4000, 1, COMMIT, "n24 #30 C15 commit 1"),
	OP(MARK, PMGR, 0, 0, COMMIT, "commit 1's time"),
	OP(AIC_MASK, PMGR, 0, 0, AIC, "n24 #31 C16 AIC mask-all"),
	OP(CRUMB, PMGR, 0, 0x60, COMMIT, "Linux: crumb 0x60, commit 1 taken (hybrid bit 28)"),
	/* pd145/pd158: read the event, the alarm, the irq mask, then arm (no 0x1406 read) */
	PMU(PMU_R, PMU_RTC_EVENT, 1, PMU, "n24 #32 C17 PMU rtc_alarm_event read"),
	PMU(PMU_ALARM, PMU_RTC_ALARM, 0, PMU, "n24 #32 C17 PMU rtc_alarm ← now + alarm_s"),
	PMU(PMU_W8, PMU_RTC_IRQ_MASK, 0, PMU, "n24 #32 C17 PMU rtc_irq_mask ← 0"),
	PMU(PMU_W8, PMU_RTC_ALARM_CTRL, PMU_RTC_ALARM_ARM, PMU, "n24 #32 C17 PMU rtc_alarm_ctrl ← 0x41"),
	OP(CRUMB, PMGR, 0, 0x61, COMMIT, "Linux: crumb 0x61, the alarm written (hybrid bit 28)"),
	OP(GATE, PMGR, 0, SEQ_GATE_PMU | SEQ_GATE_ALARM, COMMIT, "Linux: no commit 2 unless the alarm reads back armed"),
	OP(CRUMB, PMGR, 0, 0x62, COMMIT, "Linux: crumb 0x62, before commit 2's wait (hybrid bit 28)"),
	OP(UNTIL, PMGR, 0, SEQ_COMMIT_GAP_US, COMMIT, "commit 2 no sooner than macOS's 0.52 ms"),
	W32(COMMIT, 0x4000, 1, COMMIT, "n24 #33 C18 commit 2"),
	OP(CRUMB, PMGR, 29, 0x63, COMMIT, "Linux: crumb 0x63, commit 2 taken (hybrid bits 28 and 29)"),
	OP(BOOT_DEEP, PMGR, 0, 0, ALL, "n24 #34 cpu0: ACC_OVRD deep, CYC_OVRD | 0x3000001, WFI"),
};

static const struct apple_sleep_seq_soc t6020_sleep_seq = {
	.blocks = t6020_blocks,
	.nblocks = T6020_BLOCKS,
	.entry = t6020_entry,
	.nentry = ARRAY_SIZE(t6020_entry),
	.cpu_start_blk = T6020_PMGR,
	.cpu_start_off = T6020_CPU_START,
	.pmu_blk = T6020_NUB_SPMI,
	.pmu_sid = T6020_PMU_SID,
	.commit_blk = T6020_COMMIT,
	.slc_blk = T6020_MCC,
	.slc_off = 0x1c00,
	.noread_blocks = BIT(T6020_DVFS_E) | BIT(T6020_CPM_E) | BIT(T6020_DVFS_P0) |
			 BIT(T6020_CPM_P0) | BIT(T6020_DVFS_P1) | BIT(T6020_CPM_P1),
	.dispext_asc = { T6020_DCPEXT0_ASC, T6020_DCPEXT1_ASC },
	.ndispext = 2,
	.dispext_report_bit = { 14, 15 },	/* report@e pmp-dispext0, report@f pmp-dispext1 */
	.report_blk = T6020_PMS,
	.report_read = 0x2000,		/* pmp-report.c t602x: tgt_read, tgt_write, actual, status */
	.report_write = T6020_PMP_REPORT,
	.report_actual = 0x2080,
	.report_status = 0x10,
};

static const struct of_device_id apple_sleep_seq_of_match[] = {
	{ .compatible = "apple,t6020-sleep", .data = &t6020_sleep_seq },
	{}
};

/* The crumb first (0x33), and why the probe leaves: native bring-up has no console to say it */
static int apple_sleep_seq_probe(struct platform_device *pdev)
{
	int ret;

	apple_spmi_boot_crumb(0x33);
	ret = __apple_sleep_seq_probe(pdev);
	dev_info(&pdev->dev, "probe: %d (hyp mode %d, bench %d, dry_run %d)\n", ret,
		 is_kernel_in_hyp_mode(), bench, dry_run);

	return ret;
}

static struct platform_driver apple_sleep_seq_driver = {
	.driver = {
		.name = "apple-sleep-seq",
		.of_match_table = apple_sleep_seq_of_match,
		.suppress_bind_attrs = true,
		.pm = pm_sleep_ptr(&aseq_pm_ops),
	},
	.probe = apple_sleep_seq_probe,
};
builtin_platform_driver(apple_sleep_seq_driver);
