// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Apple Generic RTKit helper coprocessor
 * Copyright The Asahi Linux Contributors
 */

#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/soc/apple/rtkit.h>
#include <linux/soc/apple/sleep.h>
#include <linux/suspend.h>
#ifdef CONFIG_ARM64
#include <asm/virt.h>
#endif

#define APPLE_ASC_CPU_CONTROL		0x44
#define APPLE_ASC_CPU_CONTROL_RUN	BIT(4)

struct apple_rtkit_helper {
	struct device *dev;
	struct apple_rtkit *rtk;

	/* The firmware was told the AP is going to sleep. */
	bool ap_idle;
	/* It was told, gave no answer, and wasn't told otherwise. */
	bool idle_unanswered;
	/* Ends a sleep whose .prepare failed, which gets no .complete. */
	struct notifier_block pm_nb;

	void __iomem *asc_base;

	struct resource *sram;
	void __iomem *sram_base;
};

static int apple_rtkit_helper_shmem_setup(void *cookie, struct apple_rtkit_shmem *bfr)
{
	struct apple_rtkit_helper *helper = cookie;
	struct resource res = {
		.start = bfr->iova,
		.end = bfr->iova + bfr->size - 1,
		.name = "rtkit_map",
	};

	if (!bfr->iova) {
		bfr->buffer = dma_alloc_coherent(helper->dev, bfr->size,
						    &bfr->iova, GFP_KERNEL);
		if (!bfr->buffer)
			return -ENOMEM;
		return 0;
	}

	if (!helper->sram) {
		dev_err(helper->dev,
			"RTKit buffer request with no SRAM region: %pR", &res);
		return -EFAULT;
	}

	res.flags = helper->sram->flags;

	if (res.end < res.start || !resource_contains(helper->sram, &res)) {
		dev_err(helper->dev,
			"RTKit buffer request outside SRAM region: %pR", &res);
		return -EFAULT;
	}

	bfr->iomem = helper->sram_base + (res.start - helper->sram->start);
	bfr->is_mapped = true;

	return 0;
}

static void apple_rtkit_helper_shmem_destroy(void *cookie, struct apple_rtkit_shmem *bfr)
{
	// no-op
}

static const struct apple_rtkit_ops apple_rtkit_helper_ops = {
	.shmem_setup = apple_rtkit_helper_shmem_setup,
	.shmem_destroy = apple_rtkit_helper_shmem_destroy,
};

/*
 * A system sleep (aurora's rtkit-helper, by function): macOS tells the MTP only
 * AP 0x201 at its sleep, the first coprocessor it tells, and AP on after the
 * wake; the firmware idles and its power domain gates itself. Only for a
 * suspend via firmware: s2idle and a daily suspend send nothing, as before.
 */
static int apple_rtkit_helper_ap_power(struct apple_rtkit_helper *helper, bool on)
{
	int ret = apple_rtkit_ap_power(helper->rtk, on);

	if (ret)
		dev_err(helper->dev, "AP power notice (%s) not answered: %d\n",
			on ? "on" : "idle", ret);
	/*
	 * Nothing is sent to undo an unanswered idle notice, which macOS never does:
	 * the end of the sleep looks whether a late answer came, and only then sends AP on.
	 */
	if (ret && !on)
		helper->idle_unanswered = true;
	return ret;
}

static int apple_rtkit_helper_ap_idle(struct apple_rtkit_helper *helper)
{
	int ret;

	if (helper->ap_idle)
		return 0;
	ret = apple_rtkit_helper_ap_power(helper, false);
	if (ret)
		return ret;
	helper->ap_idle = true;
	dev_dbg(helper->dev, "AP idle notice answered for a sleep\n");
	return 0;
}

static void apple_rtkit_helper_ap_on(struct apple_rtkit_helper *helper)
{
	if (!helper->ap_idle)
		return;
	helper->ap_idle = false;
	if (!apple_rtkit_helper_ap_power(helper, true))
		dev_dbg(helper->dev, "AP on notice answered after a sleep\n");
}

/*
 * macOS tells this coprocessor first of all. Told before any driver stops its own,
 * an unanswered notice refuses a sleep that has stopped nothing yet.
 */
static int __maybe_unused apple_rtkit_helper_prepare(struct device *dev)
{
	if (!pm_suspend_via_firmware())
		return 0;
	return apple_rtkit_helper_ap_idle(dev_get_drvdata(dev));
}

static void apple_rtkit_helper_sleep_end(struct apple_rtkit_helper *helper)
{
	if (helper->idle_unanswered) {
		bool late = !apple_rtkit_is_running(helper->rtk);

		helper->idle_unanswered = false;
		dev_info(helper->dev, "after the unanswered idle notice: %s\n",
			 late ? "its answer came late, sending AP on" :
				"still no answer, nothing sent");
		helper->ap_idle = late;
	}
	apple_rtkit_helper_ap_on(helper);
}

/* A sleep refused before this device's .suspend never calls its .resume. */
static void __maybe_unused apple_rtkit_helper_complete(struct device *dev)
{
	apple_rtkit_helper_sleep_end(dev_get_drvdata(dev));
}

/* The PM core calls no .complete after a failed .prepare: end that sleep here. */
static int apple_rtkit_helper_pm_notify(struct notifier_block *nb, unsigned long action,
					void *data)
{
	struct apple_rtkit_helper *helper = container_of(nb, struct apple_rtkit_helper, pm_nb);

	if (action == PM_POST_SUSPEND && helper->idle_unanswered)
		apple_rtkit_helper_sleep_end(helper);
	return NOTIFY_DONE;
}

static void apple_rtkit_helper_pm_unregister(void *data)
{
	struct apple_rtkit_helper *helper = data;

	unregister_pm_notifier(&helper->pm_nb);
}

static int apple_rtkit_helper_pm_register(struct apple_rtkit_helper *helper)
{
	int ret;

	helper->pm_nb.notifier_call = apple_rtkit_helper_pm_notify;
	ret = register_pm_notifier(&helper->pm_nb);
	if (ret)
		return ret;
	return devm_add_action_or_reset(helper->dev, apple_rtkit_helper_pm_unregister, helper);
}

/* A firmware-driven suspend keeps this coprocessor running: it hears the AP's state only. */
static int __maybe_unused apple_rtkit_helper_suspend(struct device *dev)
{
	if (pm_suspend_via_firmware())
		return apple_rtkit_helper_ap_idle(dev_get_drvdata(dev));
	return 0;
}

/* After a firmware-driven suspend's idle notice; nothing otherwise. */
static int __maybe_unused apple_rtkit_helper_resume(struct device *dev)
{
	apple_rtkit_helper_ap_on(dev_get_drvdata(dev));
	return 0;
}

static const struct dev_pm_ops apple_rtkit_helper_pm_ops = {
	.prepare = pm_sleep_ptr(apple_rtkit_helper_prepare),
	.complete = pm_sleep_ptr(apple_rtkit_helper_complete),
	.suspend = pm_sleep_ptr(apple_rtkit_helper_suspend),
	.resume = pm_sleep_ptr(apple_rtkit_helper_resume),
};

/*
 * The m1n1 bench's t6020 sleep (native5, Tanabota notes/sleep/49): the sleep's table
 * runs this with interrupts off (sleep-seq MTPIDLE), so the AP idle's ack is polled.
 * No IOP state and no CPU stop: the run bit stays set.
 */
static int apple_rtkit_helper_sleep_seq_stop(void *data)
{
	struct apple_rtkit_helper *helper = data;
	unsigned int us;

	if (!apple_rtkit_is_running(helper->rtk))
		return -ENODEV;
	if (apple_rtkit_ap_idle_polled(helper->rtk, &us))
		return 1;
	helper->ap_idle = true;
	return 0;
}

static void apple_rtkit_helper_sleep_unregister(void *dev)
{
	apple_sleep_coproc_unregister(dev);
}

/*
 * Below EL2 only, where the registry takes it only on the bench: no ASC is given, so
 * nothing clears its run bit; its stop is the AP idle notice above.
 */
static void apple_rtkit_helper_sleep_register(struct apple_rtkit_helper *helper)
{
#ifdef CONFIG_ARM64
	if (is_kernel_in_hyp_mode())
		return;
	if (apple_sleep_coproc_register(helper->dev, NULL, false,
					apple_rtkit_helper_sleep_seq_stop, helper))
		return;
	if (devm_add_action_or_reset(helper->dev, apple_rtkit_helper_sleep_unregister,
				     helper->dev))
		return;
	dev_info(helper->dev, "bench sleep: AP idle notice registered as its stop\n");
#endif
}

static int apple_rtkit_helper_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct apple_rtkit_helper *helper;
	int ret;

	/* 44 bits for addresses in standard RTKit requests */
	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(44));
	if (ret)
		return ret;

	helper = devm_kzalloc(dev, sizeof(*helper), GFP_KERNEL);
	if (!helper)
		return -ENOMEM;

	helper->dev = dev;
	platform_set_drvdata(pdev, helper);

	helper->asc_base = devm_platform_ioremap_resource_byname(pdev, "asc");
	if (IS_ERR(helper->asc_base))
		return PTR_ERR(helper->asc_base);

	helper->sram = platform_get_resource_byname(pdev, IORESOURCE_MEM, "sram");
	if (helper->sram) {
		helper->sram_base = devm_ioremap_resource(dev, helper->sram);
		if (IS_ERR(helper->sram_base))
			return dev_err_probe(dev, PTR_ERR(helper->sram_base),
					"Failed to map SRAM region");
	}

	helper->rtk =
		devm_apple_rtkit_init(dev, helper, NULL, 0, &apple_rtkit_helper_ops);
	if (IS_ERR(helper->rtk))
		return dev_err_probe(dev, PTR_ERR(helper->rtk),
				     "Failed to intialize RTKit");

	writel_relaxed(APPLE_ASC_CPU_CONTROL_RUN,
		       helper->asc_base + APPLE_ASC_CPU_CONTROL);

	/* Works for both wake and boot */
	ret = apple_rtkit_wake(helper->rtk);
	if (ret != 0)
		return dev_err_probe(dev, ret, "Failed to wake up coprocessor");

	apple_rtkit_helper_sleep_register(helper);

	return apple_rtkit_helper_pm_register(helper);
}

static void apple_rtkit_helper_remove(struct platform_device *pdev)
{
	struct apple_rtkit_helper *helper = platform_get_drvdata(pdev);

	if (apple_rtkit_is_running(helper->rtk))
		apple_rtkit_quiesce(helper->rtk);

	writel_relaxed(0, helper->asc_base + APPLE_ASC_CPU_CONTROL);
}

static const struct of_device_id apple_rtkit_helper_of_match[] = {
	{ .compatible = "apple,rtk-helper-asc4" },
	{},
};
MODULE_DEVICE_TABLE(of, apple_rtkit_helper_of_match);

static struct platform_driver apple_rtkit_helper_driver = {
	.driver = {
		.name = "rtkit-helper",
		.of_match_table = apple_rtkit_helper_of_match,
		.pm = pm_sleep_ptr(&apple_rtkit_helper_pm_ops),
	},
	.probe = apple_rtkit_helper_probe,
	.remove = apple_rtkit_helper_remove,
};
module_platform_driver(apple_rtkit_helper_driver);

MODULE_AUTHOR("Hector Martin <marcan@marcan.st>");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("Apple RTKit helper driver");
