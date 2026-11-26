// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * The GPU's firmware across a firmware-driven suspend (S2R) on t6020, behind asahi.sleep_s2r
 * (Tanabota notes/sleep/m2pro-73-gpu-s2r-design.md). Off, nothing here runs and sleep-seq's
 * table stops gfx-asc's CPU bare, as before.
 *
 * On, the firmware is idled as macOS does (AP 0x201, IOP 0x201, acks polled) by sleep-seq's
 * GFX row through the stop registered here, with interrupts off and every refusal behind it
 * (bit 0), or by .prepare with interrupts on (bit 1, a bench arm), or by suspend_late with
 * interrupts on (bit 2, sleep_s2r=4): a device that refuses the sleep in the device phase then
 * aborts it before the idle, with the firmware untouched. After a real wake the
 * session restarts warm: the firmware's DRAM, rings and page tables are kept, so only the
 * RTKit handshake is repeated (aurora's G16/G17, our internal DCP). Whether the G14X 13.5
 * firmware takes that is the open question this tests.
 *
 * A sleep that doesn't happen after the idle (a device's refusal, an abort before the commit)
 * finds the firmware idled with its power kept and its CPU still running: it is woken as RTKit's
 * own idle/wake pair does, without a restart (Tanabota notes/sleep/m2pro-73-gpu-abort.md).
 */
#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/of_platform.h>
#include <linux/io.h>
#include <linux/mfd/syscon.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/suspend.h>
#include <linux/workqueue.h>
#include <linux/soc/apple/boot-crumb.h>
#include <linux/soc/apple/pmp-report.h>
#include <linux/soc/apple/rtkit.h>
#include <linux/soc/apple/sleep.h>

#define ASAHI_S2R_ON		BIT(0)
#define ASAHI_S2R_PREPARE_IDLE	BIT(1)
/* sleep_s2r=4: the idle at suspend_late, after every device's .suspend (implies bit 0) */
#define ASAHI_S2R_LATE_IDLE	BIT(2)
/*
 * Bit 7: withdraw AGX's PMP report again 1 s after the warm restart, as macOS's wake does (0x700, then 0x300 with GFX
 * off). Left raised through GPU work, the PMP doesn't answer its idle at the next sleep (Tanabota m2pro-73-port.md,
 * blip-series 11-26). Bit 8: retry it every second until the PMP follows, up to 30 tries.
 */
#define ASAHI_S2R_AGX_BLIP	BIT(7)
#define ASAHI_S2R_AGX_BLIP_RETRY	BIT(8)
/*
 * Bit 9: the withdrawal in .complete itself, right after the kick and the device-control round trip, while every task
 * is still frozen and the GPU has no work, polled up to 1 s. After the thaw a drawing client keeps the PMP's AGX bit on
 * (bits 7/8 then fail); with it a held client kept all 4 sleeps in 3 of 3 bench runs (blip3, 11-26).
 */
#define ASAHI_S2R_AGX_SYNC	BIT(9)

#define ASC_CPU_CONTROL		0x44
#define ASC_CPU_CONTROL_RUN	BIT(4)

#define PS_ACTUAL		GENMASK(7, 4)

/* t6020's PMP report: bit 10 is AGX (iop-pmp-nub soc-device), macOS 0x700 at the wake */
#define PMP_REPORT_AGX		10

/* PMU boot_stage crumbs (boot-crumb.h's free range; 0xe3 is iBoot's, 0xee taken) */
#define GPU_CRUMB_RESTART	0xe8
#define GPU_CRUMB_PS_ON		0xe9
#define GPU_CRUMB_HELLO		0xea
#define GPU_CRUMB_FAILED	0xeb
#define GPU_CRUMB_KICKED	0xec
#define GPU_CRUMB_NO_RESUME	0xed

struct asahi_s2r {
	struct device *dev;
	struct apple_rtkit *rtk;
	void __iomem *asc;
	struct regmap *ps_map;
	u32 ps_off;
	u32 flags;
	/* A crashed firmware at .prepare: nothing to keep, the row's bare CPU stop alone */
	bool skip;
	/* .complete gave the GPU up (the caller failed its jobs): every later sleep skips it too */
	bool lost;
	/* The last stop: its result, the time its acks took, GFX PS at the stop */
	int stop_ret;
	unsigned int stop_us;
	u32 stop_ps;
	bool idled;
	/* bit 2: .prepare armed this sleep; suspend_late's idle result (-ENODATA: not reached) */
	bool armed;
	int late_ret;
	/* bit 2: GPU -> PMP, so the GPU's suspend_late runs before the PMP's stop */
	struct device_link *pmp_link;
};

static struct asahi_s2r asahi_s2r;

static u32 asahi_s2r_ps(struct asahi_s2r *s)
{
	u32 val = 0;

	if (s->ps_map)
		regmap_read(s->ps_map, s->ps_off, &val);
	return val;
}

static unsigned int asahi_s2r_blip_tries;
static void asahi_s2r_blip_fn(struct work_struct *w);
static DECLARE_DELAYED_WORK(asahi_s2r_blip, asahi_s2r_blip_fn);

static void asahi_s2r_blip_fn(struct work_struct *w)
{
	struct asahi_s2r *s = &asahi_s2r;
	int r;

	if (!s->dev)
		return;
	r = apple_pmp_report_set(PMP_REPORT_AGX, false);
	asahi_s2r_blip_tries++;
	if (r && (s->flags & ASAHI_S2R_AGX_BLIP_RETRY) && asahi_s2r_blip_tries < 30) {
		schedule_delayed_work(&asahi_s2r_blip, HZ);
		return;
	}
	dev_info(s->dev, "s2r: AGX's PMP report withdrawn after the wake: %d (try %u, GFX PS %#x)\n", r,
		 asahi_s2r_blip_tries, asahi_s2r_ps(s));
}

/* sleep-seq's GFX row (apple,coprocs[5]), interrupts off: the idle; the row stops the CPU */
static int asahi_s2r_stop(void *data)
{
	struct asahi_s2r *s = data;

	s->stop_us = 0;
	s->stop_ps = asahi_s2r_ps(s);
	if (s->idled || s->skip)
		return 0;
	/* bit 2: the idle was suspend_late's; no commit idle of a firmware it didn't idle */
	if (s->flags & ASAHI_S2R_LATE_IDLE) {
		s->stop_ret = -ENOENT;
		return 0;
	}
	/* An auto-gated ASC may not answer (pd385): its mailbox is left alone */
	if (s->ps_map && !FIELD_GET(PS_ACTUAL, s->stop_ps)) {
		s->stop_ret = -EAGAIN;
		return 0;
	}
	s->stop_ret = apple_rtkit_sleep_idle_polled(s->rtk, s->asc + ASC_CPU_CONTROL, &s->stop_us);
	s->idled = !s->stop_ret;

	/* Told to idle, it can't carry on: the sleep goes on whatever it answered */
	return 0;
}

/*
 * The idle needs the PMP running: it powers GFX up for the acks. On sleep-seq's S2R the PMP
 * stops in its own suspend_late (pmp-export.c), and suspend_late runs in reverse dpm_list
 * order, which DT order and deferred probes set: a stateless link (ordering only) puts the GPU
 * after the PMP in that list, so its suspend_late always comes first.
 */
static void asahi_s2r_link_pmp(struct asahi_s2r *s)
{
	struct device_node *np;
	struct platform_device *pmp = NULL;

	np = of_find_compatible_node(NULL, NULL, "apple,t6000-pmp-v2");
	if (np && of_device_is_available(np))
		pmp = of_find_device_by_node(np);
	of_node_put(np);
	if (!pmp) {
		dev_info(s->dev, "s2r: no PMP device: suspend_late order left to the dpm list\n");
		return;
	}
	s->pmp_link = device_link_add(s->dev, &pmp->dev, DL_FLAG_STATELESS);
	if (!s->pmp_link)
		dev_warn(s->dev, "s2r: no link to %s: suspend_late order left to the dpm list\n",
			 dev_name(&pmp->dev));
	put_device(&pmp->dev);
}

int asahi_s2r_register(struct device *dev, struct apple_rtkit *rtk, u32 flags);
int asahi_s2r_register(struct device *dev, struct apple_rtkit *rtk, u32 flags)
{
	struct asahi_s2r *s = &asahi_s2r;
	struct platform_device *pdev = to_platform_device(dev);
	struct device_node *np;
	struct resource *res;
	int ret;

	if (flags & ASAHI_S2R_LATE_IDLE)
		flags = (flags | ASAHI_S2R_ON) & ~ASAHI_S2R_PREPARE_IDLE;
	if (!(flags & ASAHI_S2R_ON) || !rtk)
		return 0;

	/*
	 * Mapped without a request: probe's start_cpu maps the same page for itself. The soc bus is
	 * nonposted-mmio: a posted write to the ASC may come back as an asynchronous SError (pd339).
	 * Any failure leaves the GPU as it was without the param, never fails the probe.
	 */
	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "asc");
	if (!res) {
		dev_warn(dev, "s2r: no asc resource: the GPU is cut as before\n");
		return 0;
	}
	s->asc = (res->flags & IORESOURCE_MEM_NONPOSTED) ?
		 ioremap_np(res->start, ASC_CPU_CONTROL + 8) :
		 ioremap(res->start, ASC_CPU_CONTROL + 8);
	if (!s->asc) {
		dev_warn(dev, "s2r: asc not mapped: the GPU is cut as before\n");
		return 0;
	}

	np = of_parse_phandle(dev->of_node, "power-domains", 0);
	if (np) {
		if (!of_property_read_u32(np, "reg", &s->ps_off) && np->parent) {
			s->ps_map = syscon_node_to_regmap(np->parent);
			if (IS_ERR(s->ps_map))
				s->ps_map = NULL;
		}
		of_node_put(np);
	}

	s->dev = dev;
	s->rtk = rtk;
	s->flags = flags;
	s->skip = false;
	s->lost = false;

	ret = apple_sleep_coproc_register(dev, NULL, false, asahi_s2r_stop, s);
	if (ret) {
		dev_warn(dev, "s2r: no sleep stop registered (%d): the GPU is cut as before\n", ret);
		s->dev = NULL;
		iounmap(s->asc);
		s->asc = NULL;
		return 0;
	}
	if (flags & ASAHI_S2R_LATE_IDLE)
		asahi_s2r_link_pmp(s);
	dev_info(dev, "s2r: firmware idle at %s, warm restart after a real wake (flags %#x, PS %#x)\n",
		 flags & ASAHI_S2R_LATE_IDLE ? "suspend_late" :
		 flags & ASAHI_S2R_PREPARE_IDLE ? ".prepare" : "the commit", flags, asahi_s2r_ps(s));

	return 0;
}

void asahi_s2r_unregister(struct device *dev);
void asahi_s2r_unregister(struct device *dev)
{
	if (asahi_s2r.dev != dev)
		return;
	cancel_delayed_work_sync(&asahi_s2r_blip);
	apple_sleep_coproc_unregister(dev);
	if (asahi_s2r.pmp_link) {
		device_link_del(asahi_s2r.pmp_link);
		asahi_s2r.pmp_link = NULL;
	}
	asahi_s2r.dev = NULL;
	iounmap(asahi_s2r.asc);
	asahi_s2r.asc = NULL;
}

int asahi_s2r_prepare(struct device *dev);
int asahi_s2r_prepare(struct device *dev)
{
	struct asahi_s2r *s = &asahi_s2r;
	int ret;

	if (s->dev != dev || !pm_suspend_via_firmware())
		return 0;

	cancel_delayed_work_sync(&asahi_s2r_blip);
	s->idled = false;
	s->stop_ret = -ENODATA;
	s->late_ret = -ENODATA;
	/*
	 * A crashed firmware has nothing to keep: the sleep goes on with the bare CPU stop, as
	 * without the param, rather than being refused until a reboot. .complete leaves it crashed.
	 */
	s->skip = s->lost || apple_rtkit_is_crashed(s->rtk);
	if (s->skip) {
		dev_warn(dev, "s2r: firmware crashed before the sleep: not idled, not restarted\n");
	} else if (s->flags & ASAHI_S2R_PREPARE_IDLE) {
		/* Arm B: a refused sleep after this loses the GPU until a reboot */
		ret = apple_rtkit_idle(s->rtk);
		if (ret)
			return ret;
		s->idled = true;
	}
	s->armed = !s->skip;
	apple_sleep_coproc_set_ready(dev, true);

	return 0;
}

/*
 * Bit 2: the idle, after every device's .suspend, interrupts still on (arm 3's call). A
 * refusal before this point leaves the firmware running; one after it loses the GPU as arm 3's
 * does. Refused, the sleep is aborted and the firmware carries on (a failed idle is mode 3's
 * refusal too).
 */
int asahi_s2r_suspend_late(struct device *dev);
int asahi_s2r_suspend_late(struct device *dev)
{
	struct asahi_s2r *s = &asahi_s2r;
	int ret;

	if (s->dev != dev || !(s->flags & ASAHI_S2R_LATE_IDLE) || !s->armed ||
	    !pm_suspend_via_firmware())
		return 0;

	ret = apple_rtkit_idle(s->rtk);
	s->late_ret = ret;
	if (ret) {
		dev_err(dev, "s2r: idle at suspend_late failed: %d (GFX PS %#x): refusing the sleep\n",
			ret, asahi_s2r_ps(s));
		return ret;
	}
	s->idled = true;
	dev_info(dev, "s2r: firmware idle at suspend_late, GFX PS %#x\n", asahi_s2r_ps(s));

	return 0;
}

/*
 * A sleep that didn't happen: the GPU kept its power. With the run bit set the CPU was only
 * idled (arm B's .prepare idle; a commit idle whose row stop didn't follow), so it is woken
 * the way RTKit wakes any idled coprocessor: IOP INIT 0x220, the IOP ON ack, AP ON, with the
 * session (endpoints, buffers, rings) kept and no HELLO waited for. G16's failure after a
 * refusal was a restart that waits for a discovery an idle never gives up; this isn't one.
 * With the run bit clear the commit's row stopped it, and nothing after the commit goes back
 * (sleep.c): it stays down until the next real sleep's warm restart, or a reboot.
 * Returns 1 if the firmware is back (the caller kicks it and checks a round trip).
 */
static int asahi_s2r_abort(struct asahi_s2r *s, struct device *dev, bool row_stopped, bool run)
{
	int ret;

	apple_spmi_boot_crumb(GPU_CRUMB_NO_RESUME);
	if (!run) {
		dev_err(dev, "s2r: stopped at the commit for a sleep that didn't happen: GPU down until reboot\n");
		s->lost = true;
		return -ENODEV;
	}

	/* The commit's PMP row withdrew AGX's report only if it ran */
	if (row_stopped) {
		ret = apple_pmp_report_set(PMP_REPORT_AGX, true);
		if (ret && ret != -ENODEV)
			dev_warn(dev, "s2r: PMP report AGX request: %d\n", ret);
	}

	/* AP ON alone if only the AP idle took (0 if neither did); -EAGAIN: both took */
	ret = apple_rtkit_sleep_return(s->rtk, s->asc + ASC_CPU_CONTROL);
	if (ret == -EAGAIN)
		ret = apple_rtkit_wake(s->rtk);
	s->idled = false;
	if (ret) {
		apple_spmi_boot_crumb(GPU_CRUMB_FAILED);
		dev_err(dev, "s2r: no wake from the idle after a sleep that didn't happen: %d (GFX PS %#x, run bit %s): GPU down until reboot\n",
			ret, asahi_s2r_ps(s),
			readl(s->asc + ASC_CPU_CONTROL) & ASC_CPU_CONTROL_RUN ? "set" : "clear");
		s->lost = true;
		return ret;
	}
	apple_spmi_boot_crumb(GPU_CRUMB_HELLO);
	dev_info(dev, "s2r: firmware woken from the idle after a sleep that didn't happen, GFX PS %#x\n",
		 asahi_s2r_ps(s));

	return 1;
}

/*
 * Returns 1 if the firmware was restarted or woken (the caller kicks it), 0 if nothing was
 * stopped, a negative error if it is down: the caller fails its jobs.
 */
int asahi_s2r_complete(struct device *dev);
int asahi_s2r_complete(struct device *dev)
{
	struct asahi_s2r *s = &asahi_s2r;
	bool row_stopped, stopped, run;
	u32 ps;
	int ret;

	if (s->dev != dev)
		return 0;
	row_stopped = apple_sleep_coproc_stopped(dev);
	stopped = row_stopped ||
		  (s->flags & (ASAHI_S2R_PREPARE_IDLE | ASAHI_S2R_LATE_IDLE) && s->idled);
	apple_sleep_coproc_set_ready(dev, false);
	if (s->flags & ASAHI_S2R_LATE_IDLE && s->armed) {
		s->armed = false;
		if (!stopped && s->late_ret == -ENODATA) {
			dev_info(dev, "s2r: the sleep didn't happen before the idle, firmware untouched\n");
			return 0;
		}
		if (!stopped) {
			/* A half-taken idle (AP only) is undone by the abort path's sleep_return */
			dev_warn(dev, "s2r: idle at suspend_late refused (%d): undoing what took\n",
				 s->late_ret);
			stopped = true;
		} else if (!pm_resume_via_firmware()) {
			dev_err(dev, "s2r: the sleep didn't happen after the suspend_late idle (row %s): trying the idle's wake, else the GPU is lost\n",
				row_stopped ? "stopped" : "not run");
		}
	}
	if (!stopped)
		return 0;
	if (s->skip) {
		s->lost = true;
		return -ENODEV;
	}

	run = readl(s->asc + ASC_CPU_CONTROL) & ASC_CPU_CONTROL_RUN;
	dev_info(dev, "s2r: stop %d after %u us, GFX PS %#x at the stop, run bit %s, %s\n",
		 s->stop_ret, s->stop_us, s->stop_ps, run ? "set" : "clear",
		 pm_resume_via_firmware() ? "woke" : "no sleep");

	if (!pm_resume_via_firmware())
		return asahi_s2r_abort(s, dev, row_stopped, run);

	apple_spmi_boot_crumb(GPU_CRUMB_RESTART);
	ps = asahi_s2r_ps(s);
	ret = apple_pmp_report_set(PMP_REPORT_AGX, true);
	if (ret && ret != -ENODEV)
		dev_warn(dev, "s2r: PMP report AGX request: %d\n", ret);
	if (s->ps_map && !FIELD_GET(PS_ACTUAL, ps))
		dev_warn(dev, "s2r: GFX PS %#x not on after the resync\n", ps);
	apple_spmi_boot_crumb(GPU_CRUMB_PS_ON);

	ret = apple_rtkit_power_cycled_return(s->rtk, s->asc + ASC_CPU_CONTROL);
	s->idled = false;
	if (ret) {
		apple_spmi_boot_crumb(GPU_CRUMB_FAILED);
		dev_err(dev, "s2r: warm restart failed: %d (GFX PS %#x, run bit %s)\n", ret,
			asahi_s2r_ps(s),
			readl(s->asc + ASC_CPU_CONTROL) & ASC_CPU_CONTROL_RUN ? "set" : "clear");
		s->lost = true;
		return ret;
	}
	apple_spmi_boot_crumb(GPU_CRUMB_HELLO);
	/* The kick is the caller's (kick_firmware, under the driver's RTKit lock): one, not two */
	dev_info(dev, "s2r: firmware restarted warm, GFX PS %#x\n", asahi_s2r_ps(s));
	if (s->flags & ASAHI_S2R_AGX_BLIP) {
		asahi_s2r_blip_tries = 0;
		schedule_delayed_work(&asahi_s2r_blip, HZ);
	}

	return 1;
}

/* The caller's kick after a warm restart went out */
void asahi_s2r_kicked(void);
void asahi_s2r_kicked(void)
{
	apple_spmi_boot_crumb(GPU_CRUMB_KICKED);
}

/* Bit 9: from .complete after the kick and the device-control round trip, tasks still frozen */
void asahi_s2r_withdraw_now(void);
void asahi_s2r_withdraw_now(void)
{
	struct asahi_s2r *s = &asahi_s2r;
	ktime_t t0 = ktime_get();
	int r, tries = 0;

	if (!s->dev || !(s->flags & ASAHI_S2R_AGX_SYNC))
		return;
	do {
		r = apple_pmp_report_set(PMP_REPORT_AGX, false);
		tries++;
		if (!r)
			break;
		usleep_range(10000, 20000);
	} while (ktime_ms_delta(ktime_get(), t0) < 1000);
	dev_info(s->dev, "s2r: AGX's PMP report withdrawn in complete: %d (try %d, %lld ms, GFX PS %#x)\n", r, tries,
		 ktime_ms_delta(ktime_get(), t0), asahi_s2r_ps(s));
}
