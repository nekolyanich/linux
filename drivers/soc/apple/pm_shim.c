// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * System sleep for the SEP driver: the notifier only forwards "about to sleep"
 * and "back from sleep" to Rust, which ends any Touch ID capture before the
 * system suspends (see pm.rs), and the enclave's power domains are kept on
 * across sleep.
 */
#include <linux/compiler.h>
#include <linux/device.h>
#include <linux/iopoll.h>
#include <linux/mfd/syscon.h>
#include <linux/notifier.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <linux/pm_domain.h>
#include <linux/regmap.h>
#include <linux/soc/apple/boot-crumb.h>
#include <linux/soc/apple/dart.h>
#include <linux/soc/apple/sleep.h>
#include <linux/suspend.h>

#include "shim.h"

static int (*sep_pm_event)(bool entering);

static int sep_pm_notify(struct notifier_block *nb, unsigned long action,
			 void *data)
{
	int (*event)(bool entering) = READ_ONCE(sep_pm_event);

	if (!event)
		return NOTIFY_DONE;

	switch (action) {
	case PM_SUSPEND_PREPARE:
	case PM_HIBERNATION_PREPARE:
	case PM_RESTORE_PREPARE:
		return notifier_from_errno(event(true));
	case PM_POST_SUSPEND:
	case PM_POST_HIBERNATION:
	case PM_POST_RESTORE:
		event(false);
		return NOTIFY_OK;
	default:
		return NOTIFY_DONE;
	}
}

static struct notifier_block sep_pm_nb = {
	.notifier_call = sep_pm_notify,
};

int sep_pm_register(int (*event)(bool entering))
{
	int ret;

	WRITE_ONCE(sep_pm_event, event);
	ret = register_pm_notifier(&sep_pm_nb);
	if (ret)
		WRITE_ONCE(sep_pm_event, NULL);
	return ret;
}

/* Returns only once no notifier call is still running. */
void sep_pm_unregister(void)
{
	unregister_pm_notifier(&sep_pm_nb);
	WRITE_ONCE(sep_pm_event, NULL);
}

/*
 * The m1n1 bench's early SLEEP (apple_sleep.sep_sleep_early; native5, aurora #1664, JJRPF's
 * R18 on T6020), the only SEP sleep this driver sends: at device suspend the enclave is
 * asked to save its state and gate its own power domain, its DART held first; suspend_noirq
 * waits for the domain's gating; resume starts it again. Every other sleep, and every daily
 * boot, sends nothing: the callbacks return at once. The SLEEP left to the commit's table
 * (apple_sleep.sep_sleep) isn't carried.
 */
#define SEP_PS_DEV_DISABLE	BIT(10)

static int (*sep_pm_sleep)(void);
static void (*sep_pm_wake)(bool real);
static bool (*sep_pm_told)(void);

/* The enclave's own domain is the first one its node lists. */
static int sep_pm_domain(struct device *dev, struct regmap **regmap, u32 *offset)
{
	struct device_node *np;
	int ret;

	np = of_parse_phandle(dev->of_node, "power-domains", 0);
	if (!np)
		return -ENOENT;

	*regmap = syscon_node_to_regmap(np->parent);
	ret = PTR_ERR_OR_ZERO(*regmap);
	if (!ret)
		ret = of_property_read_u32(np, "reg", offset);
	of_node_put(np);

	return ret;
}

/*
 * 0 once the enclave has gated itself, 1 if the deadline expired, or a negative read
 * error (-ENOENT without a domain). DEV_DISABLE is the evidence: a running enclave idles
 * at actual state 0 with auto-enable on.
 */
static int sep_pm_wait_gated(struct device *dev, unsigned int timeout_ms)
{
	struct regmap *regmap;
	u32 offset, val;
	int ret, poll_ret;

	ret = sep_pm_domain(dev, &regmap, &offset);
	if (ret)
		return ret;

	poll_ret = read_poll_timeout(regmap_read, ret, ret || (val & SEP_PS_DEV_DISABLE),
				     1000, timeout_ms * USEC_PER_MSEC, false,
				     regmap, offset, &val);
	if (ret)
		return ret;

	return !!poll_ret;
}

int sep_pm_clear_dev_disable(void *ptr)
{
	struct regmap *regmap;
	u32 offset, val;
	int ret;

	ret = sep_pm_domain(ptr, &regmap, &offset);
	if (ret)
		return ret;

	ret = regmap_read(regmap, offset, &val);
	if (ret || !(val & SEP_PS_DEV_DISABLE))
		return ret;

	return regmap_write(regmap, offset, val & ~SEP_PS_DEV_DISABLE);
}

/* The enclave's DART, the first one its node lists, with a reference held. */
static struct device *sep_pm_dart(struct device *dev)
{
	struct platform_device *pdev;
	struct device_node *np;

	np = of_parse_phandle(dev->of_node, "iommus", 0);
	if (!np)
		return NULL;
	pdev = of_find_device_by_node(np);
	of_node_put(np);

	return pdev ? &pdev->dev : NULL;
}

/* At the wake, before the doorbell: the DART back if its power went with the enclave's. */
void sep_pm_dart_restore(void *ptr)
{
	struct device *dart = sep_pm_dart(ptr);

	if (dart) {
		apple_dart_sleep_restore_lost(dart, pm_resume_via_firmware());
		put_device(dart);
	}
}

/*
 * The DART goes down with the enclave's domain (ADT dart-sep has no power-gates of its
 * own): saved and left alone before the send, as macOS's mapper deactivation does before
 * cmsgSLEEP. @hold false gives it back unchanged, for a request never sent.
 */
int sep_pm_dart_hold(void *ptr, bool hold)
{
	struct device *dart = sep_pm_dart(ptr);
	int ret = 0;

	if (!dart)
		return -ENODEV;
	if (hold)
		ret = apple_dart_sleep_hold_any(dart);
	else
		apple_dart_sleep_restore_lost(dart, false);
	put_device(dart);

	return ret;
}

/*
 * Bench crumbs (PMU boot_stage, native EL2 with spmi_apple_controller.boot_crumb=1 only):
 * 0x5a .suspend entered, 0x5b SLEEP sent, 0x5c taken (param 0), 0x5d refused (param != 0),
 * 0x5e no answer, 0x5f DEV_DISABLE seen in .suspend_noirq, 0x59 its timeout.
 */
void sep_pm_crumb(u8 stage)
{
	apple_spmi_boot_crumb(stage);
}

/* Only a suspend to RAM: s2idle doesn't power the enclave down, and its wake isn't real */
static bool sep_pm_early_sleep(void)
{
	return apple_sleep_bench_sep_sleep_early() && pm_suspend_target_state == PM_SUSPEND_MEM;
}

static int __maybe_unused sep_pm_suspend(struct device *dev)
{
	int (*sleep)(void) = READ_ONCE(sep_pm_sleep);

	if (!sep_pm_early_sleep() || !sleep)
		return 0;
	sep_pm_crumb(0x5a);
	return sleep();
}

/* Whether the enclave has gated itself, now */
bool sep_pm_gated(void *ptr)
{
	return !sep_pm_wait_gated(ptr, 0);
}

/* The last step before the platform's own: the domain has to be down by now. */
static int __maybe_unused sep_pm_suspend_noirq(struct device *dev)
{
	bool (*told)(void) = READ_ONCE(sep_pm_told);
	int ret;

	if (!sep_pm_early_sleep() || !told || !told())
		return 0;

	ret = sep_pm_wait_gated(dev, 5000);
	if (ret > 0)
		ret = -ETIMEDOUT;
	if (ret == -ENOENT)
		return 0;
	sep_pm_crumb(ret ? 0x59 : 0x5f);
	if (ret)
		dev_err(dev, "the enclave did not gate its power domain: %d\n", ret);
	else
		dev_info(dev, "the enclave gated its power domain\n");
	return ret;
}

static int __maybe_unused sep_pm_resume(struct device *dev)
{
	void (*wake)(bool real) = READ_ONCE(sep_pm_wake);

	if (wake)
		wake(pm_resume_via_firmware());
	return 0;
}

const struct dev_pm_ops sep_pm_ops = {
	.suspend = pm_sleep_ptr(sep_pm_suspend),
	.resume = pm_sleep_ptr(sep_pm_resume),
	.suspend_noirq = pm_sleep_ptr(sep_pm_suspend_noirq),
};

/* The driver's SleepGate (open, draining, told, lost), for sysfs; rv-sepkey's (d) */
static u32 sep_pm_gate;
static const char *const sep_pm_gate_names[] = { "open", "draining", "told", "lost", "refused" };

void sep_pm_set_gate(u32 gate)
{
	WRITE_ONCE(sep_pm_gate, gate);
	apple_sleep_sep_gate_set(gate);
}

static ssize_t sleep_gate_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	u32 gate = READ_ONCE(sep_pm_gate);

	return sysfs_emit(buf, "%s\n", gate < ARRAY_SIZE(sep_pm_gate_names) ?
			  sep_pm_gate_names[gate] : "?");
}
static DEVICE_ATTR_RO(sleep_gate);

int sep_pm_register_sleep(void *ptr, int (*sleep)(void), void (*wake)(bool real), bool (*told)(void))
{
	WRITE_ONCE(sep_pm_sleep, sleep);
	WRITE_ONCE(sep_pm_wake, wake);
	WRITE_ONCE(sep_pm_told, told);
	apple_sleep_sep_early_set(ptr, true);
	return device_create_file(ptr, &dev_attr_sleep_gate);
}

void sep_pm_unregister_sleep(void *ptr)
{
	device_remove_file(ptr, &dev_attr_sleep_gate);
	apple_sleep_sep_early_set(ptr, false);
	WRITE_ONCE(sep_pm_sleep, NULL);
	WRITE_ONCE(sep_pm_wake, NULL);
	WRITE_ONCE(sep_pm_told, NULL);
}

static void sep_pm_release_domains(void *data)
{
	struct dev_pm_domain_list *list = data;
	u32 i;

	for (i = 0; i < list->num_pds; i++)
		dev_pm_syscore_device(list->pd_devs[i], false);
}

/*
 * The enclave runs from boot to shutdown, and on some SoCs it needs power
 * domains besides its own: once one of them is switched off, it stops
 * reading its mailbox for good. A node that lists more than one domain gets
 * all of them attached here, powered on through device links for as long as
 * the driver is bound, and taken out of system sleep, which would otherwise
 * switch a domain off in the noirq phase once its other users had suspended.
 * A node with a single domain is attached by the platform core as before.
 */
int sep_pm_keep_domains(void *ptr)
{
	struct device *dev = ptr;
	struct dev_pm_domain_attach_data data = {
		.pd_flags = PD_FLAG_DEV_LINK_ON,
	};
	struct dev_pm_domain_list *list;
	int count, ret;
	u32 i;

	count = of_count_phandle_with_args(dev->of_node, "power-domains",
					   "#power-domain-cells");
	if (count <= 1)
		return 0;

	ret = devm_pm_domain_attach_list(dev, &data, &list);
	if (ret < 0)
		return ret;

	for (i = 0; i < list->num_pds; i++)
		dev_pm_syscore_device(list->pd_devs[i], true);

	return devm_add_action_or_reset(dev, sep_pm_release_domains, list);
}
