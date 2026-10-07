/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * Apple display switch: hand the external DCPs out to DisplayPort sinks
 *
 * Apple Silicon routes any external DCP (an "upstream facing port") to any
 * DisplayPort source of a Type-C port (a "downstream facing port"): the
 * port's DP PHY for DP alt mode, or one of the DP IN adapters of its USB4
 * host router for DP tunnelled over USB4. The drivers that see a sink come
 * and go report it here; appledrm picks a free DCP and routes it.
 */

#ifndef _LINUX_SOC_APPLE_DP_SWITCH_H
#define _LINUX_SOC_APPLE_DP_SWITCH_H

#include <linux/types.h>

/* the DFP port numbers the ADT and DCP's connectTo target use */
#define APPLE_DP_SWITCH_DPPHY	0
#define APPLE_DP_SWITCH_DPIN0	1
#define APPLE_DP_SWITCH_DPIN1	2

#if IS_REACHABLE(CONFIG_DRM_APPLE)
/**
 * apple_dp_switch_hotplug() - Report a DisplayPort sink on a Type-C port
 * @die: die of the port's ATC
 * @atc: ATC (Type-C port) index
 * @port: APPLE_DP_SWITCH_DPPHY or APPLE_DP_SWITCH_DPIN0/1
 * @connected: whether a sink is there
 *
 * Does not sleep; repeated reports of the same state are ignored.
 */
void apple_dp_switch_hotplug(u32 die, u32 atc, u32 port, bool connected);
#else
static inline void apple_dp_switch_hotplug(u32 die, u32 atc, u32 port,
					   bool connected)
{
}
#endif

#endif /* _LINUX_SOC_APPLE_DP_SWITCH_H */
