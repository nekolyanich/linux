// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * The PMP across a system sleep (aurora's pmp-export.c, by function, for t6020's
 * t6000-pmp-v2, which keeps no SRAM): idled and its CPU stopped with its RTKit
 * session kept, and restarted warm after a real wake. With apple_pmp.bench_sleep
 * (the m1n1 bench, as native5's t4-a ran) at suspend_late; otherwise, for a
 * suspend via firmware, at the sleep's commit through apple-sleep's coprocessor
 * registry. Any other sleep leaves it running, as before.
 */
#include <linux/device.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/pm.h>
#include <linux/soc/apple/pmp.h>
#include <linux/soc/apple/rtkit.h>
#include <linux/soc/apple/sleep.h>
#include <linux/suspend.h>

#define APPLE_PMP_ASC_CPU_CONTROL	0x44

static DEFINE_MUTEX(pmp_lock);
static struct device *pmp_device;
static struct apple_rtkit *pmp_rtk;
static void __iomem *pmp_asc;
static bool pmp_asleep, pmp_commit_registered, pmp_commit_used;

static bool bench_sleep;
module_param(bench_sleep, bool, 0444);
MODULE_PARM_DESC(bench_sleep, "bench: idle and stop the PMP at suspend_late without suspend_via_firmware");

int apple_pmp_register(struct device *dev, struct apple_rtkit *rtk)
{
	int idx;

	guard(mutex)(&pmp_lock);
	if (pmp_device)
		return -EBUSY;
	idx = of_property_match_string(dev->of_node, "reg-names", "asc");
	pmp_asc = idx >= 0 ? of_iomap(dev->of_node, idx) : NULL;
	if (!pmp_asc)
		return -ENOMEM;
	pmp_device = dev;
	pmp_rtk = rtk;
	return 0;
}

void apple_pmp_unregister(struct device *dev)
{
	guard(mutex)(&pmp_lock);
	if (pmp_device != dev)
		return;
	if (pmp_commit_registered)
		apple_sleep_coproc_unregister(dev);
	pmp_commit_registered = false;
	iounmap(pmp_asc);
	pmp_asc = NULL;
	pmp_rtk = NULL;
	pmp_device = NULL;
}

/* Interrupts off, one CPU: the idle pair, polled. sleep-seq clears the run bit after. */
static int apple_pmp_commit_stop_fn(void *unused)
{
	unsigned int us;

	return apple_rtkit_sleep_idle_polled(pmp_rtk, pmp_asc + APPLE_PMP_ASC_CPU_CONTROL, &us);
}

static bool apple_pmp_commit_available(struct device *dev)
{
	if (pmp_commit_registered)
		return true;
	if (apple_sleep_coproc_register(dev, pmp_asc, false, apple_pmp_commit_stop_fn, NULL))
		return false;
	pmp_commit_registered = true;
	return true;
}

static int apple_pmp_suspend_late(struct device *dev)
{
	bool at_commit;
	int ret;

	if (!pm_suspend_via_firmware() && !bench_sleep)
		return 0;

	guard(mutex)(&pmp_lock);
	if (pmp_device != dev || pmp_asleep || !pmp_rtk)
		return 0;
	/* The bench's sleep-seq stops no registered coprocessor at the commit: stop it here. */
	at_commit = !bench_sleep && apple_pmp_commit_available(dev);
	/* Idled any earlier, a refusal after it would leave it stopped. */
	if (!at_commit && apple_sleep_commit_stops_coprocs()) {
		dev_err(dev, "no stop at the sleep's commit: refusing the sleep\n");
		return -EBUSY;
	}
	if (at_commit) {
		apple_sleep_coproc_set_ready(dev, true);
		pmp_commit_used = true;
		dev_info(dev, "idle and stop left for the sleep's commit\n");
	} else {
		ret = apple_rtkit_sleep_stop(pmp_rtk, pmp_asc + APPLE_PMP_ASC_CPU_CONTROL);
		if (ret) {
			if (apple_rtkit_sleep_return(pmp_rtk, pmp_asc + APPLE_PMP_ASC_CPU_CONTROL))
				dev_err(dev, "firmware did not come back\n");
			return dev_err_probe(dev, ret, "firmware did not go idle for sleep\n");
		}
		dev_info(dev, "firmware idle and stopped for sleep\n");
	}
	pmp_asleep = true;
	return 0;
}

static int apple_pmp_resume_early(struct device *dev)
{
	int ret;

	guard(mutex)(&pmp_lock);
	if (!pmp_asleep)
		return 0;
	/* Left for the commit: if the sleep was refused before it, the firmware never idled. */
	if (pmp_commit_used) {
		bool stopped = apple_sleep_coproc_stopped(dev);

		pmp_commit_used = false;
		apple_sleep_coproc_set_ready(dev, false);
		if (!pm_resume_via_firmware() && !stopped) {
			pmp_asleep = false;
			dev_info(dev, "sleep refused before the commit: firmware never stopped\n");
			return 0;
		}
	}
	/* A stopped firmware doesn't restart with its power kept: the next real sleep does. */
	if (!pm_resume_via_firmware()) {
		dev_warn(dev, "sleep refused: firmware stays stopped until a real sleep\n");
		return 0;
	}
	pmp_asleep = false;
	ret = apple_rtkit_sleep_return(pmp_rtk, pmp_asc + APPLE_PMP_ASC_CPU_CONTROL);
	if (ret)
		dev_err(dev, "firmware did not come back from sleep: %d\n", ret);
	else
		dev_info(dev, "firmware back from sleep\n");
	return 0;
}

const struct dev_pm_ops apple_pmp_pm_ops = {
	LATE_SYSTEM_SLEEP_PM_OPS(apple_pmp_suspend_late, apple_pmp_resume_early)
};
