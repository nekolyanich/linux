// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * The SMC hooks sleep-seq.c calls, until the macsmc batch of the m2pro 7.3.4
 * sleep backport brings them into drivers/mfd/macsmc.c. They refuse: with
 * them a suspend stops at the SMC notice, before any cut (dry runs only).
 */
#include <linux/errno.h>
#include <linux/mfd/macsmc.h>

void apple_smc_bench_edge_keys(struct apple_smc *smc, const char *tag, bool polled)
{
}

int apple_smc_bench_read_line(struct apple_smc *smc, const smc_key *keys, int n, char *buf, size_t size,
			      bool polled)
{
	return -EOPNOTSUPP;
}

int apple_smc_sleep_seq_warn(struct apple_smc *smc)
{
	return -EOPNOTSUPP;
}

int apple_smc_sleep_seq_commit(struct apple_smc *smc, unsigned int arm_us, unsigned int idle_us,
			       bool skip_slpa)
{
	return -EOPNOTSUPP;
}
