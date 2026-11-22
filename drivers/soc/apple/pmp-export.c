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
#include <linux/soc/apple/boot-crumb.h>
#include <linux/soc/apple/rtkit.h>
#include <linux/soc/apple/sleep.h>
#include <linux/suspend.h>

#define APPLE_PMP_ASC_CPU_CONTROL	0x44

static DEFINE_MUTEX(pmp_lock);
static struct device *pmp_device;
static struct apple_rtkit *pmp_rtk;
static void __iomem *pmp_asc;
static bool pmp_asleep, pmp_commit_registered, pmp_commit_used;
/* The last real wake didn't bring it back: left stopped, not idled again (state 7) */
static bool pmp_wake_failed;

/*
 * Bench crumbs (boot_stage, EL2 with spmi_apple_controller.boot_crumb=1): 0x40 + the state at
 * suspend_late and at the commit (see apple_sleep_pmp_state_set), overwritten by the entry's
 * later crumbs; apple_sleep.pmp_crumb carries the last one to the crumb before commit 2.
 */
static void apple_pmp_state(u8 state)
{
	apple_sleep_pmp_state_set(state);
	apple_spmi_boot_crumb(0x40 + state);
}

static bool bench_sleep;
module_param(bench_sleep, bool, 0444);
MODULE_PARM_DESC(bench_sleep, "bench: idle and stop the PMP at suspend_late without suspend_via_firmware");

/*
 * Whether the PMP's stop can go to the sleep (aurora 2b629a0c, by function): the sleep driver is
 * built and the DT has an available sleep controller. Then an unbind would leave the firmware
 * running, and a commit with it running resets the SoC (seen on T8140); a rebind can't register
 * again, so every later sleep is refused until reboot. The PMP stays bound (pmp.rs) and its
 * module stays loaded (apple_pmp_register) there.
 */
bool apple_pmp_keep_bound(void)
{
	struct device_node *np;

	if (!IS_ENABLED(CONFIG_APPLE_SOC_SLEEP))
		return false;
	for_each_node_by_name(np, "sleep-controller") {
		if (of_device_is_available(np)) {
			of_node_put(np);
			return true;
		}
	}
	return false;
}

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
	apple_sleep_pmp_state_set(1);
	/* Never put: no rmmod once the PMP can be stopped for a sleep */
	if (apple_pmp_keep_bound())
		__module_get(THIS_MODULE);
	return 0;
}

void apple_pmp_unregister(struct device *dev)
{
	guard(mutex)(&pmp_lock);
	if (pmp_device != dev)
		return;
	apple_sleep_pmp_state_set(0);
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
	int ret = apple_rtkit_sleep_idle_polled(pmp_rtk, pmp_asc + APPLE_PMP_ASC_CPU_CONTROL, &us);

	/* No crumb write here: the SPMI path takes a lock the commit can't */
	apple_sleep_pmp_state_set(ret ? 6 : 5);
	return ret;
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

	if (!pm_suspend_via_firmware() && !bench_sleep) {
		apple_sleep_pmp_state_set(pmp_device == dev ? 1 : 0);
		return 0;
	}

	guard(mutex)(&pmp_lock);
	if (pmp_device == dev && pmp_wake_failed) {
		/* Stopped since the last wake: this sleep takes it as it is */
		apple_pmp_state(7);
		return 0;
	}
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
		apple_pmp_state(4);
		dev_info(dev, "idle and stop left for the sleep's commit\n");
	} else {
		ret = apple_rtkit_sleep_stop(pmp_rtk, pmp_asc + APPLE_PMP_ASC_CPU_CONTROL);
		if (ret) {
			apple_pmp_state(3);
			if (apple_rtkit_sleep_return(pmp_rtk, pmp_asc + APPLE_PMP_ASC_CPU_CONTROL))
				dev_err(dev, "firmware did not come back\n");
			return dev_err_probe(dev, ret, "firmware did not go idle for sleep\n");
		}
		apple_pmp_state(2);
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
		pmp_wake_failed = false;
			dev_info(dev, "sleep refused before the commit: firmware never stopped\n");
			return 0;
		}
	}
	/*
	 * Refused after the stop: an idled firmware doesn't wake with its power kept, and the
	 * fabric and the report acks stop with it. SIO's order (2e15ba51): sleep_return, which
	 * takes a firmware whose idle didn't finish; else the sleep engine's PMGR reset of it and
	 * a restart as after a power cycle. If neither works it stays stopped until a real sleep,
	 * pmp_asleep kept, so no later sleep tries to idle it.
	 */
	if (!pm_resume_via_firmware()) {
		void __iomem *control = pmp_asc + APPLE_PMP_ASC_CPU_CONTROL;

		if (!apple_rtkit_sleep_return(pmp_rtk, control)) {
			pmp_asleep = false;
		pmp_wake_failed = false;
			dev_info(dev, "sleep refused: firmware still ran\n");
			return 0;
		}
		ret = apple_sleep_engine_reset(dev);
		if (!ret)
			ret = apple_rtkit_power_cycled_return(pmp_rtk, control);
		if (ret) {
			dev_warn(dev, "sleep refused: firmware not back after a reset (%d), stopped until a real sleep\n",
				 ret);
			return 0;
		}
		pmp_asleep = false;
		pmp_wake_failed = false;
		dev_info(dev, "sleep refused: firmware back after a reset\n");
		return 0;
	}
	ret = apple_rtkit_sleep_return(pmp_rtk, pmp_asc + APPLE_PMP_ASC_CPU_CONTROL);
	if (ret) {
		/*
		 * Not back (x1cyc3-a: cycle 2's stop failed, 0x43): idling a firmware that never
		 * restarted fails the next sleep. Keep it stopped, as after a cut, and say so in the
		 * crumbs (0x47 here, and at each later suspend_late; 0xc7 with pmp_crumb).
		 */
		pmp_wake_failed = true;
		apple_pmp_state(7);
		dev_err(dev, "firmware did not come back from sleep: %d, left stopped\n", ret);
		return 0;
	}
	pmp_asleep = false;
	pmp_wake_failed = false;
	dev_info(dev, "firmware back from sleep\n");
	return 0;
}

const struct dev_pm_ops apple_pmp_pm_ops = {
	LATE_SYSTEM_SLEEP_PM_OPS(apple_pmp_suspend_late, apple_pmp_resume_early)
};
