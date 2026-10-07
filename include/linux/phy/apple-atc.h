/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * Apple Type-C PHY: DisplayPort tunnelled over USB4
 */

#ifndef _LINUX_PHY_APPLE_ATC_H
#define _LINUX_PHY_APPLE_ATC_H

#include <linux/errno.h>
#include <linux/types.h>

struct phy;

#if IS_REACHABLE(CONFIG_PHY_APPLE_ATC)
int apple_atc_dp_tunnel_rate(struct phy *phy, u8 rate);
#else
static inline int apple_atc_dp_tunnel_rate(struct phy *phy, u8 rate)
{
	return -ENODEV;
}
#endif

#endif /* _LINUX_PHY_APPLE_ATC_H */
