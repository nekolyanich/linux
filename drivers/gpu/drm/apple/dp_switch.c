// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Display switch: hands the external DCPs out to DisplayPort sinks on the
 * Type-C ports, as macOS's dp-switch does (ADT display-crossbar0: DCPs are
 * its upstream facing ports, (atc, dpphy/dpin0/dpin1) its downstream facing
 * ones, and DCP's connectTo target names exactly such a pair).
 */

#include <linux/mutex.h>
#include <linux/soc/apple/dp-switch.h>
#include <linux/workqueue.h>

#include "dcp-internal.h"
#include "dcp.h"

#define DP_SWITCH_DIES	2
#define DP_SWITCH_ATCS	8
#define DP_SWITCH_PORTS	3
#define DP_SWITCH_DFPS	(DP_SWITCH_DIES * DP_SWITCH_ATCS * DP_SWITCH_PORTS)
#define DP_SWITCH_UFPS	4

struct dp_switch_dfp {
	bool hpd;
	struct apple_dcp *dcp;
};

static struct {
	struct mutex lock;
	struct dp_switch_dfp dfp[DP_SWITCH_DFPS];
	struct apple_dcp *ufp[DP_SWITCH_UFPS];
} dp_switch = {
	.lock = __MUTEX_INITIALIZER(dp_switch.lock),
};

static void dp_switch_work(struct work_struct *work);
static DECLARE_WORK(dp_switch_work_item, dp_switch_work);

static unsigned int dfp_index(u32 die, u32 atc, u32 port)
{
	return (die * DP_SWITCH_ATCS + atc) * DP_SWITCH_PORTS + port;
}

static void dfp_decode(unsigned int i, u32 *die, u32 *atc, u32 *port)
{
	*port = i % DP_SWITCH_PORTS;
	*atc = (i / DP_SWITCH_PORTS) % DP_SWITCH_ATCS;
	*die = i / (DP_SWITCH_PORTS * DP_SWITCH_ATCS);
}

static bool ufp_busy(struct apple_dcp *dcp)
{
	for (int i = 0; i < DP_SWITCH_DFPS; i++)
		if (dp_switch.dfp[i].dcp == dcp)
			return true;
	return false;
}

/*
 * macOS drives DP alt mode from the lowest external DCP and tunnels from the
 * highest (traced with both at once on t6020), so prefer that and fall back
 * to any free one.
 */
static struct apple_dcp *ufp_pick(bool tunnel)
{
	struct apple_dcp *best = NULL;

	for (int i = 0; i < DP_SWITCH_UFPS; i++) {
		struct apple_dcp *dcp = dp_switch.ufp[i];

		if (!dcp || ufp_busy(dcp) || !dcp_switch_available(dcp))
			continue;
		if (!best || (tunnel ? dcp->index > best->index :
				       dcp->index < best->index))
			best = dcp;
	}
	return best;
}

static void dp_switch_work(struct work_struct *work)
{
	u32 die, atc, port;
	int i;

	mutex_lock(&dp_switch.lock);

	/* release first, so a DCP freed here can take a waiting sink */
	for (i = 0; i < DP_SWITCH_DFPS; i++) {
		struct dp_switch_dfp *dfp = &dp_switch.dfp[i];

		if (dfp->hpd || !dfp->dcp)
			continue;
		dfp_decode(i, &die, &atc, &port);
		dev_info(dfp->dcp->dev, "dp-switch: atc%u port %u released\n",
			 atc, port);
		dcp_switch_disconnect(dfp->dcp);
		dfp->dcp = NULL;
	}

	for (i = 0; i < DP_SWITCH_DFPS; i++) {
		struct dp_switch_dfp *dfp = &dp_switch.dfp[i];
		struct apple_dcp *dcp;
		int ret;

		if (!dfp->hpd || dfp->dcp)
			continue;
		dfp_decode(i, &die, &atc, &port);
		dcp = ufp_pick(port != APPLE_DP_SWITCH_DPPHY);
		if (!dcp) {
			pr_info("apple-dp-switch: no free DCP for die %u atc%u port %u\n",
				die, atc, port);
			continue;
		}
		dev_info(dcp->dev, "dp-switch: taking die %u atc%u port %u\n",
			 die, atc, port);
		dfp->dcp = dcp;
		ret = dcp_switch_connect(dcp, die, atc, port);
		if (ret) {
			dev_warn(dcp->dev, "dp-switch: connect failed: %d\n", ret);
			dcp_switch_disconnect(dcp);
			dfp->dcp = NULL;
		}
	}

	mutex_unlock(&dp_switch.lock);
}

void apple_dp_switch_hotplug(u32 die, u32 atc, u32 port, bool connected)
{
	struct dp_switch_dfp *dfp;

	if (die >= DP_SWITCH_DIES || atc >= DP_SWITCH_ATCS ||
	    port >= DP_SWITCH_PORTS)
		return;

	dfp = &dp_switch.dfp[dfp_index(die, atc, port)];
	if (READ_ONCE(dfp->hpd) == connected)
		return;
	WRITE_ONCE(dfp->hpd, connected);
	pr_info("apple-dp-switch: die %u atc%u port %u %s\n", die, atc, port,
		connected ? "connected" : "disconnected");
	schedule_work(&dp_switch_work_item);
}
EXPORT_SYMBOL_GPL(apple_dp_switch_hotplug);

/* a DCP whose DPTX endpoint just came up may take a waiting sink */
void dp_switch_kick(void)
{
	schedule_work(&dp_switch_work_item);
}

int dp_switch_add_dcp(struct apple_dcp *dcp)
{
	int ret = -ENOSPC;

	mutex_lock(&dp_switch.lock);
	for (int i = 0; i < DP_SWITCH_UFPS; i++) {
		if (!dp_switch.ufp[i]) {
			dp_switch.ufp[i] = dcp;
			ret = 0;
			break;
		}
	}
	mutex_unlock(&dp_switch.lock);
	return ret;
}

void dp_switch_remove_dcp(struct apple_dcp *dcp)
{
	flush_work(&dp_switch_work_item);
	mutex_lock(&dp_switch.lock);
	for (int i = 0; i < DP_SWITCH_DFPS; i++) {
		if (dp_switch.dfp[i].dcp == dcp) {
			dcp_switch_disconnect(dcp);
			dp_switch.dfp[i].dcp = NULL;
		}
	}
	for (int i = 0; i < DP_SWITCH_UFPS; i++)
		if (dp_switch.ufp[i] == dcp)
			dp_switch.ufp[i] = NULL;
	mutex_unlock(&dp_switch.lock);
}
