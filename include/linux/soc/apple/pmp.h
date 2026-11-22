/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
#ifndef _LINUX_SOC_APPLE_PMP_H_
#define _LINUX_SOC_APPLE_PMP_H_

#include <linux/pm.h>

struct apple_rtkit;
struct device;

/* pmp-export.c: the PMP driver's sleep across a system suspend */
int apple_pmp_register(struct device *dev, struct apple_rtkit *rtk);
void apple_pmp_unregister(struct device *dev);
bool apple_pmp_keep_bound(void);
extern const struct dev_pm_ops apple_pmp_pm_ops;

#endif
