// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * The two sleep-seq hooks sleep.c calls, until sleep-seq.c itself arrives
 * (m2pro 7.3.4 sleep backport, batch 1 builds the framework alone; batch 2
 * replaces this file with sleep-seq.c): no bench, no SEP SLEEP.
 */
#include <linux/export.h>
#include <linux/soc/apple/sleep.h>

#include "sleep-aura.h"

bool apple_sleep_bench_sep_sleep(void)
{
	return false;
}
EXPORT_SYMBOL_GPL(apple_sleep_bench_sep_sleep);

bool apple_sleep_seq_bench(void)
{
	return false;
}
