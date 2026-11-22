/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * The boot object's half of an Apple SoC system sleep: the mailbox it publishes in
 * /chosen/aurora,s2r-mailbox, shared by the sleep drivers of this directory.
 */
#ifndef _APPLE_SLEEP_AURA_H_
#define _APPLE_SLEEP_AURA_H_

#include <linux/types.h>

struct device;

/* Must match aura's struct aura_s2r_mailbox. */
#define AURA_S2R_MAGIC		0x3152325341525541ULL	/* "AURAS2R1" */

struct aura_s2r_mailbox {
	u64 magic;		/* aura, before the kernel starts */
	u64 boot_mpidr;		/* aura: the only core that may take resume_pa */
	u64 resume_pa;		/* kernel, armed before a commit; aura clears it */
	u64 resumes;		/* aura: resume_pa taken this many times */
	/* Tanabota native S2R (m1n1 bench/native-1); size 48, an older boot object ignores them */
	u64 edge_cntpct;	/* kernel: CNTPCT right before cpu0's WFI, cleaned to PoC; the boot object's re-gate window starts here */
	u64 regates;		/* boot object: cpu0's early bounces it sent back into the WFI, before the real wake */
};

/* sleep-seq.c's apple_sleep.bench: the m1n1 bench, EL1 under its hypervisor */
bool apple_sleep_seq_bench(void);

/* The SEP's staged SLEEP (pm_shim's enclave stop): the bench's table driver, IRQs off */
bool apple_sleep_enclave_staged(void);
int apple_sleep_enclave_send(void);

/* A registered co-processor's last check, then its last stop: the bench's table driver, IRQs off */
int apple_sleep_coproc_stop(struct device *dev);
bool apple_sleep_coproc_registered(struct device *dev);

#endif
