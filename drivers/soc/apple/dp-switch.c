// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Apple display switch: where the Type-C and USB4 drivers report DisplayPort
 * sinks, and where appledrm picks them up. Built in, so the reporters and
 * appledrm may each be built in or modular, and a sink reported before
 * appledrm loads is handed over when it registers.
 */

#include <linux/bitmap.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/soc/apple/dp-switch.h>
#include <linux/spinlock.h>

#define DP_SWITCH_DFPS (APPLE_DP_SWITCH_DIES * APPLE_DP_SWITCH_ATCS * \
			APPLE_DP_SWITCH_PORTS)

static DEFINE_SPINLOCK(dp_switch_lock);
static DECLARE_BITMAP(dp_switch_hpd, DP_SWITCH_DFPS);
static apple_dp_switch_handler_t dp_switch_handler;

static unsigned int dfp_index(u32 die, u32 atc, u32 port)
{
	return (die * APPLE_DP_SWITCH_ATCS + atc) * APPLE_DP_SWITCH_PORTS + port;
}

void apple_dp_switch_hotplug(u32 die, u32 atc, u32 port, bool connected)
{
	unsigned int i;
	unsigned long flags;

	if (die >= APPLE_DP_SWITCH_DIES || atc >= APPLE_DP_SWITCH_ATCS ||
	    port >= APPLE_DP_SWITCH_PORTS)
		return;

	i = dfp_index(die, atc, port);
	spin_lock_irqsave(&dp_switch_lock, flags);
	if (test_bit(i, dp_switch_hpd) != connected) {
		assign_bit(i, dp_switch_hpd, connected);
		pr_info("apple-dp-switch: die %u atc%u port %u %s\n", die, atc,
			port, connected ? "connected" : "disconnected");
		if (dp_switch_handler)
			dp_switch_handler(die, atc, port, connected);
	}
	spin_unlock_irqrestore(&dp_switch_lock, flags);
}
EXPORT_SYMBOL_GPL(apple_dp_switch_hotplug);

int apple_dp_switch_register(apple_dp_switch_handler_t handler)
{
	unsigned long flags;
	unsigned int i;
	int ret = 0;

	spin_lock_irqsave(&dp_switch_lock, flags);
	if (dp_switch_handler) {
		ret = -EBUSY;
		goto out;
	}
	dp_switch_handler = handler;
	for_each_set_bit(i, dp_switch_hpd, DP_SWITCH_DFPS)
		handler(i / (APPLE_DP_SWITCH_ATCS * APPLE_DP_SWITCH_PORTS),
			(i / APPLE_DP_SWITCH_PORTS) % APPLE_DP_SWITCH_ATCS,
			i % APPLE_DP_SWITCH_PORTS, true);
out:
	spin_unlock_irqrestore(&dp_switch_lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_dp_switch_register);

void apple_dp_switch_unregister(void)
{
	unsigned long flags;

	spin_lock_irqsave(&dp_switch_lock, flags);
	dp_switch_handler = NULL;
	spin_unlock_irqrestore(&dp_switch_lock, flags);
}
EXPORT_SYMBOL_GPL(apple_dp_switch_unregister);
