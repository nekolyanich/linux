/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
#ifndef _LINUX_SOC_APPLE_PMP_REPORT_H_
#define _LINUX_SOC_APPLE_PMP_REPORT_H_

#include <linux/errno.h>
#include <linux/types.h>

#if IS_ENABLED(CONFIG_APPLE_PMP_REPORT)
/* A request in the PMP report outside genpd, locked against its entries, acknowledged */
int apple_pmp_report_set(unsigned int id, bool enable);
#else
static inline int apple_pmp_report_set(unsigned int id, bool enable)
{
	return -ENODEV;
}
#endif

#endif
