/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * Apple display switch: hand the external DCPs out to DisplayPort sinks
 *
 * Apple Silicon routes any external DCP (an "upstream facing port") to any
 * DisplayPort source of a Type-C port (a "downstream facing port"): the
 * port's DP PHY for DP alt mode, or one of the DP IN adapters of its USB4
 * host router for DP tunnelled over USB4. The drivers that see a sink come
 * and go report it here; appledrm registers to pick a free DCP and route it.
 */

#ifndef _LINUX_SOC_APPLE_DP_SWITCH_H
#define _LINUX_SOC_APPLE_DP_SWITCH_H

#include <linux/errno.h>
#include <linux/types.h>

struct notifier_block;

/* the DFP port numbers the ADT and DCP's connectTo target use */
#define APPLE_DP_SWITCH_DPPHY	0
#define APPLE_DP_SWITCH_DPIN0	1
#define APPLE_DP_SWITCH_DPIN1	2

#define APPLE_DP_SWITCH_DIES	2
#define APPLE_DP_SWITCH_ATCS	8
#define APPLE_DP_SWITCH_PORTS	3

/* called with a spinlock held, must not sleep */
typedef void (*apple_dp_switch_handler_t)(u32 die, u32 atc, u32 port,
					  bool connected);

#if IS_ENABLED(CONFIG_APPLE_DP_SWITCH)
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

/*
 * The display driver's side: @handler gets every change, and right away every
 * sink already connected.
 */
int apple_dp_switch_register(apple_dp_switch_handler_t handler);
void apple_dp_switch_unregister(void);

/*
 * A DCP became free for the switch. A sink whose source gave up waiting for a
 * DCP (a DP tunnel whose DPRX timed out) is not reported again by itself, so
 * its driver listens here to offer it once more. Process context.
 */
void apple_dp_switch_dcp_free(void);
int apple_dp_switch_register_dcp_free(struct notifier_block *nb);
void apple_dp_switch_unregister_dcp_free(struct notifier_block *nb);
#else
static inline void apple_dp_switch_hotplug(u32 die, u32 atc, u32 port,
					   bool connected)
{
}

static inline int apple_dp_switch_register(apple_dp_switch_handler_t handler)
{
	return -ENODEV;
}

static inline void apple_dp_switch_unregister(void)
{
}

static inline void apple_dp_switch_dcp_free(void)
{
}

static inline int apple_dp_switch_register_dcp_free(struct notifier_block *nb)
{
	return 0;
}

static inline void apple_dp_switch_unregister_dcp_free(struct notifier_block *nb)
{
}
#endif

#endif /* _LINUX_SOC_APPLE_DP_SWITCH_H */
