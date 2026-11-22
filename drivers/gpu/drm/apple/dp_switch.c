// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Display switch: hands the external DCPs out to DisplayPort sinks on the
 * Type-C ports, as macOS's dp-switch does (ADT display-crossbar0: DCPs are
 * its upstream facing ports, (atc, dpphy/dpin0/dpin1) its downstream facing
 * ones, and DCP's connectTo target names exactly such a pair).
 */

#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/soc/apple/dp-switch.h>
#include <linux/suspend.h>
#include <linux/workqueue.h>

#include "dcp-internal.h"
#include "dcp.h"

#define DP_SWITCH_DIES	APPLE_DP_SWITCH_DIES
#define DP_SWITCH_ATCS	APPLE_DP_SWITCH_ATCS
#define DP_SWITCH_PORTS	APPLE_DP_SWITCH_PORTS
#define DP_SWITCH_DFPS	(DP_SWITCH_DIES * DP_SWITCH_ATCS * DP_SWITCH_PORTS)
#define DP_SWITCH_UFPS	4

struct dp_switch_dfp {
	bool hpd;
	/* went away since the last pass, even if it is back already */
	bool gone;
	struct apple_dcp *dcp;
};

static struct {
	struct mutex lock;
	struct dp_switch_dfp dfp[DP_SWITCH_DFPS];
	struct apple_dcp *ufp[DP_SWITCH_UFPS];
	bool kicked;
	/* sleep_hold: every route released for the sleep, no pass until the resume work */
	bool held;
} dp_switch = {
	.lock = __MUTEX_INITIALIZER(dp_switch.lock),
};

static const char *const dp_switch_port_names[DP_SWITCH_PORTS] = {
	"dpphy", "dpin0", "dpin1"
};

static void dp_switch_work(struct work_struct *work);
static DECLARE_WORK(dp_switch_work_item, dp_switch_work);

/*
 * rv-dpswitch round 2 (Q4 #2, aurora's sleep_held idea, d2ff12e2, our mechanics): release every
 * route at PM_SUSPEND_PREPARE, while everything is still powered (dcp_switch_disconnect deselects
 * the crossbar and stops the tunnel clock), then record hotplug events but run no pass until
 * PM_POST_SUSPEND, which routes again. The pass runs on the non-freezable system_wq: without the
 * hold, a tunnel torn down at the entry would run a pass against DCPs being stopped. Off by
 * default: a daily sleep keeps the routes, and the replug at PM_POST_SUSPEND, as now.
 */
static bool sleep_hold;
module_param(sleep_hold, bool, 0444);
MODULE_PARM_DESC(sleep_hold, "Release the display switch's routes for system sleep, route again after it");

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
	bool freed;
	u32 die, atc, port;
	int i;

	mutex_lock(&dp_switch.lock);
	/* sleep_hold: the events, and a kick, are kept for the pass after the sleep */
	if (dp_switch.held) {
		mutex_unlock(&dp_switch.lock);
		return;
	}
	freed = xchg(&dp_switch.kicked, false);

	/* release first, so a DCP freed here can take a waiting sink */
	for (i = 0; i < DP_SWITCH_DFPS; i++) {
		struct dp_switch_dfp *dfp = &dp_switch.dfp[i];
		bool gone = xchg(&dfp->gone, false);

		/*
		 * A sink that went and came back between two passes (a USB4
		 * link that dropped and retrained) is a new sink: its old
		 * route goes, and the loop below routes it afresh.
		 */
		if (!dfp->dcp || (dfp->hpd && !gone))
			continue;
		dfp_decode(i, &die, &atc, &port);
		dev_info(dfp->dcp->dev, "dp-switch: releasing atc%u %s\n",
			 atc, dp_switch_port_names[port]);
		dcp_switch_disconnect(dfp->dcp, false);
		dfp->dcp = NULL;
		freed = true;
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
			pr_warn("apple-dp-switch: no free display controller for atc%u %s\n",
				atc, dp_switch_port_names[port]);
			continue;
		}
		dev_info(dcp->dev, "dp-switch: driving atc%u %s\n",
			 atc, dp_switch_port_names[port]);
		dfp->dcp = dcp;
		ret = dcp_switch_connect(dcp, die, atc, port);
		if (ret) {
			dev_warn(dcp->dev, "dp-switch: connect failed: %d\n", ret);
			dcp_switch_disconnect(dcp, false);
			dfp->dcp = NULL;
		}
	}

	/* a DCP is still free: offer it to sinks that stopped waiting for one */
	freed = freed && ufp_pick(true);
	mutex_unlock(&dp_switch.lock);

	if (freed)
		apple_dp_switch_dcp_free();
}

/*
 * A sink driven across system sleep stays dark: DCP's modeset on resume runs
 * mid-resume and the sink does not take it, while the same modeset later does.
 * Once the system is fully up, take every route down and plug it again, as a
 * replug of the cable would.
 */
static void dp_switch_resume_work(struct work_struct *work)
{
	u32 die, atc, port;
	bool released = false;

	mutex_lock(&dp_switch.lock);
	for (int i = 0; i < DP_SWITCH_DFPS; i++) {
		struct dp_switch_dfp *dfp = &dp_switch.dfp[i];

		if (!dfp->dcp)
			continue;
		dfp_decode(i, &die, &atc, &port);
		dev_info(dfp->dcp->dev, "dp-switch: replugging atc%u %s after sleep\n",
			 atc, dp_switch_port_names[port]);
		dcp_switch_disconnect(dfp->dcp, false);
		dfp->dcp = NULL;
		released = true;
	}
	/*
	 * sleep_hold released them at the prepare already (so the loop above found none): the
	 * hold ends here, not at PM_POST_SUSPEND, so no pass routes before this pause (one blink).
	 */
	if (dp_switch.held) {
		dp_switch.held = false;
		released = true;
	}
	mutex_unlock(&dp_switch.lock);

	if (released) {
		/* give DCP the pause a cable pull would */
		msleep(1000);
		schedule_work(&dp_switch_work_item);
	}
}
static DECLARE_WORK(dp_switch_resume_work_item, dp_switch_resume_work);

static int dp_switch_pm_notify(struct notifier_block *nb, unsigned long action,
			       void *data)
{
	u32 die, atc, port;

	if (action == PM_SUSPEND_PREPARE && sleep_hold) {
		/* a pass in flight finishes first: it holds the lock */
		mutex_lock(&dp_switch.lock);
		dp_switch.held = true;
		for (int i = 0; i < DP_SWITCH_DFPS; i++) {
			struct dp_switch_dfp *dfp = &dp_switch.dfp[i];

			if (!dfp->dcp)
				continue;
			dfp_decode(i, &die, &atc, &port);
			dev_info(dfp->dcp->dev, "dp-switch: releasing atc%u %s for sleep\n",
				 atc, dp_switch_port_names[port]);
			dcp_switch_disconnect(dfp->dcp, false);
			dfp->dcp = NULL;
		}
		mutex_unlock(&dp_switch.lock);
	}
	if (action == PM_POST_SUSPEND)
		schedule_work(&dp_switch_resume_work_item);
	return NOTIFY_DONE;
}

/* Whether the passes are held for a system sleep (sleep_hold): no route can be set until the resume */
bool apple_dp_switch_held(void)
{
	bool held;

	mutex_lock(&dp_switch.lock);
	held = dp_switch.held;
	mutex_unlock(&dp_switch.lock);
	return held;
}

static struct notifier_block dp_switch_pm_nb = {
	.notifier_call = dp_switch_pm_notify,
};

/* the switch core calls this with its spinlock held */
static void dp_switch_event(u32 die, u32 atc, u32 port, bool connected)
{
	if (die >= DP_SWITCH_DIES || atc >= DP_SWITCH_ATCS ||
	    port >= DP_SWITCH_PORTS)
		return;

	if (!connected)
		WRITE_ONCE(dp_switch.dfp[dfp_index(die, atc, port)].gone, true);
	WRITE_ONCE(dp_switch.dfp[dfp_index(die, atc, port)].hpd, connected);
	schedule_work(&dp_switch_work_item);
}

/* a DCP just became available (DPTX endpoint up, HDMI unplugged) */
void dp_switch_kick(void)
{
	WRITE_ONCE(dp_switch.kicked, true);
	schedule_work(&dp_switch_work_item);
}

static int dp_switch_nr_ufps(void)
{
	int n = 0;

	for (int i = 0; i < DP_SWITCH_UFPS; i++)
		n += !!dp_switch.ufp[i];
	return n;
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
	/* the first DCP takes the sinks reported so far */
	if (!ret && dp_switch_nr_ufps() == 1) {
		ret = apple_dp_switch_register(dp_switch_event);
		if (ret)
			dp_switch.ufp[0] = NULL;
		else
			register_pm_notifier(&dp_switch_pm_nb);
	}
	mutex_unlock(&dp_switch.lock);
	return ret;
}

/*
 * From the DCP's component unbind, while its DPTX endpoint and the DRM
 * objects are still there: take its sinks off it, and keep ufp_pick() away
 * from it until its DPTX endpoint comes back with the next bind and kicks.
 */
void dp_switch_unbind_dcp(struct apple_dcp *dcp)
{
	mutex_lock(&dp_switch.lock);
	for (int i = 0; i < DP_SWITCH_DFPS; i++) {
		if (dp_switch.dfp[i].dcp == dcp) {
			dcp_switch_disconnect(dcp, true);
			dp_switch.dfp[i].dcp = NULL;
		}
	}
	for (int i = 0; i < ARRAY_SIZE(dcp->dptxport); i++)
		dcp->dptxport[i].enabled = false;
	mutex_unlock(&dp_switch.lock);
}

void dp_switch_remove_dcp(struct apple_dcp *dcp)
{
	bool last;

	mutex_lock(&dp_switch.lock);
	for (int i = 0; i < DP_SWITCH_DFPS; i++) {
		if (dp_switch.dfp[i].dcp == dcp) {
			dcp_switch_disconnect(dcp, true);
			dp_switch.dfp[i].dcp = NULL;
		}
	}
	for (int i = 0; i < DP_SWITCH_UFPS; i++)
		if (dp_switch.ufp[i] == dcp)
			dp_switch.ufp[i] = NULL;
	last = !dp_switch_nr_ufps();
	if (last) {
		apple_dp_switch_unregister();
		unregister_pm_notifier(&dp_switch_pm_nb);
	}
	mutex_unlock(&dp_switch.lock);

	/*
	 * Nothing schedules them any more; the resume work schedules the
	 * other one, so it goes first. A pass for the remaining DCPs needs no
	 * waiting for: it runs under the lock and no longer sees this one.
	 */
	if (last) {
		cancel_work_sync(&dp_switch_resume_work_item);
		cancel_work_sync(&dp_switch_work_item);
	}
}
