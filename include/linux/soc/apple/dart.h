/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
#ifndef __LINUX_SOC_APPLE_DART_H__
#define __LINUX_SOC_APPLE_DART_H__

#include <linux/errno.h>
#include <linux/kconfig.h>
#include <linux/types.h>

struct device;

/*
 * The DART's registers saved and put back around its consumer's own power
 * cycle, outside a system sleep (apple-sleep, native5's dart.h). More of
 * aurora's DART sleep interface comes with the DART batch.
 */
#if IS_ENABLED(CONFIG_APPLE_DART)
int apple_dart_state_save(struct device *dev);
int apple_dart_state_restore(struct device *dev);
int apple_dart_sleep_hold(struct device *dev);
int apple_dart_sleep_hold_any(struct device *dev);
void apple_dart_sleep_restore_lost(struct device *dev, bool lost);
void apple_dart_bench_state(struct device *dev, char *buf, size_t len);
#else
static inline int apple_dart_state_save(struct device *dev)
{
	return -ENODEV;
}

static inline int apple_dart_state_restore(struct device *dev)
{
	return -ENODEV;
}

static inline int apple_dart_sleep_hold(struct device *dev)
{
	return -ENODEV;
}

static inline int apple_dart_sleep_hold_any(struct device *dev)
{
	return -ENODEV;
}

static inline void apple_dart_sleep_restore_lost(struct device *dev, bool lost)
{
}

static inline void apple_dart_bench_state(struct device *dev, char *buf, size_t len)
{
	buf[0] = 0;
}
#endif

#endif /* __LINUX_SOC_APPLE_DART_H__ */
