// SPDX-License-Identifier: GPL-2.0-only OR MIT
/* Copyright 2021 Alyssa Rosenzweig */

#include <linux/align.h>
#include <linux/bitmap.h>
#include <linux/clk.h>
#include <linux/completion.h>
#include <linux/component.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/gpio/consumer.h>
#include <linux/iommu.h>
#include <linux/jiffies.h>
#include <linux/kconfig.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/phy/apple-atc.h>
#include <linux/slab.h>
#include <linux/soc/apple/dp-switch.h>
#include <linux/iopoll.h>
#include <linux/soc/apple/dart.h>
#include <linux/soc/apple/rtkit.h>
#include <linux/soc/apple/sleep.h>
#include <linux/string.h>
#include <linux/suspend.h>
#include <linux/usb/typec_altmode.h>
#include <linux/usb/typec_dp.h>
#include <linux/usb/typec_mux.h>
#include <linux/workqueue.h>

#include <asm/virt.h>

#include <drm/drm_eld.h>
#include <drm/drm_fb_dma_helper.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_framebuffer.h>
#include <drm/drm_module.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_vblank.h>

#include "afk.h"
#include "audio.h"
#include "av.h"
#include "dcp.h"
#include "dcp-internal.h"
#include "iomfb.h"
#include "parser.h"
#include "trace.h"

#define APPLE_DCP_COPROC_CPU_CONTROL	 0x44
#define APPLE_DCP_COPROC_CPU_CONTROL_RUN BIT(4)
#define APPLE_DCP_COPROC_CPU_STATUS	 0x48
#define APPLE_DCP_COPROC_CPU_STATUS_DOWN (BIT(1) | BIT(5))

#define DCP_BOOT_TIMEOUT msecs_to_jiffies(1000)

static bool show_notch;
module_param(show_notch, bool, 0644);
MODULE_PARM_DESC(show_notch, "Use the full display height and shows the notch");

bool hdmi_audio;
module_param(hdmi_audio, bool, 0644);
MODULE_PARM_DESC(hdmi_audio, "Enable unstable HDMI audio support");

static bool unstable_edid = true;
module_param(unstable_edid, bool, 0644);
MODULE_PARM_DESC(unstable_edid, "Enable unstable EDID retrival support");

/* copied and simplified from drm_vblank.c */
static void send_vblank_event(struct drm_device *dev,
		struct drm_pending_vblank_event *e,
		u64 seq, ktime_t now)
{
	struct timespec64 tv;

	if (e->event.base.type != DRM_EVENT_FLIP_COMPLETE)
		return;

	tv = ktime_to_timespec64(now);
	e->event.vbl.sequence = seq;
	/*
		* e->event is a user space structure, with hardcoded unsigned
		* 32-bit seconds/microseconds. This is safe as we always use
		* monotonic timestamps since linux-4.15
		*/
	e->event.vbl.tv_sec = tv.tv_sec;
	e->event.vbl.tv_usec = tv.tv_nsec / 1000;

	/*
	 * Use the same timestamp for any associated fence signal to avoid
	 * mismatch in timestamps for vsync & fence events triggered by the
	 * same HW event. Frameworks like SurfaceFlinger in Android expects the
	 * retire-fence timestamp to match exactly with HW vsync as it uses it
	 * for its software vsync modeling.
	 */
	drm_send_event_timestamp_locked(dev, &e->base, now);
}

/**
 * dcp_crtc_send_page_flip_event - helper to send vblank event after pageflip
 *
 * Compensate for unknown slack between page flip and arrival of the
 * swap_complete callback. Minimal observed duration on DCP with HDMI output
 * was around 2.3 ms. If the fb swap was submitted closer to the expected
 * swap_complete it gets a penalty of one frame duration. This is on the border
 * of unreasonable considering that Apple advertises support for 240 Hz (frame
 * duration of 4.167 ms).
 * It is unreasonable considering kwin's kms commit scheduling. Kwin commits
 * 1.5 ms + the mode's vblank time before the expected next page flip
 * completion. This results in presenting at half the display's rate for HDMI
 * outputs.
 * This might be a difference between dcp and dcpext.
 */
static void dcp_crtc_send_page_flip_event(struct apple_crtc *crtc,
					  struct drm_pending_vblank_event *e,
					  ktime_t now, ktime_t start)
{
	struct drm_device *dev = crtc->base.dev;
	u64 seq;
	unsigned int pipe = drm_crtc_index(&crtc->base);
	ktime_t flip;

	seq = 0;
	if (start != KTIME_MIN) {
		s64 delta = ktime_us_delta(now, start);
		if (delta <= 500)
			flip = now;
		else if (delta >= 2500)
			flip = ktime_sub_us(now, 1000);
		else
			flip = ktime_sub_us(now, (delta - 500) / 2);
	} else {
		flip = now;
	}
	e->pipe = pipe;
	send_vblank_event(dev, e, seq, flip);
}

/* HACK: moved here to avoid circular dependency between apple_drv and dcp */
void dcp_drm_crtc_vblank(struct apple_crtc *crtc)
{
	unsigned long flags;

	spin_lock_irqsave(&crtc->base.dev->event_lock, flags);
	if (crtc->event) {
		drm_crtc_send_vblank_event(&crtc->base, crtc->event);
		crtc->event = NULL;
	}
	spin_unlock_irqrestore(&crtc->base.dev->event_lock, flags);
}

void dcp_drm_crtc_page_flip(struct apple_dcp *dcp, ktime_t now)
{
	unsigned long flags;
	struct apple_crtc *crtc = dcp->crtc;

	spin_lock_irqsave(&crtc->base.dev->event_lock, flags);
	if (crtc->event) {
		if (crtc->event->event.base.type == DRM_EVENT_FLIP_COMPLETE)
			dcp_crtc_send_page_flip_event(crtc, crtc->event, now, dcp->swap_start);
		else
			drm_crtc_send_vblank_event(&crtc->base, crtc->event);
		crtc->event = NULL;
		dcp->swap_start = KTIME_MIN;
	}
	spin_unlock_irqrestore(&crtc->base.dev->event_lock, flags);
}

void dcp_set_dimensions(struct apple_dcp *dcp)
{
	int i;
	int width_mm = dcp->width_mm;
	int height_mm = dcp->height_mm;

	if (width_mm == 0 || height_mm == 0) {
		width_mm = dcp->panel.width_mm;
		height_mm = dcp->panel.height_mm;
	}

	/* Set the connector info */
	if (dcp->connector) {
		struct drm_connector *connector = &dcp->connector->base;

		mutex_lock(&connector->dev->mode_config.mutex);
		connector->display_info.width_mm = width_mm;
		connector->display_info.height_mm = height_mm;
		mutex_unlock(&connector->dev->mode_config.mutex);
	}

	/*
	 * Fix up any probed modes. Modes are created when parsing
	 * TimingElements, dimensions are calculated when parsing
	 * DisplayAttributes, and TimingElements may be sent first
	 */
	for (i = 0; i < dcp->nr_modes; ++i) {
		dcp->modes[i].mode.width_mm = width_mm;
		dcp->modes[i].mode.height_mm = height_mm;
	}
}

bool dcp_has_panel(struct apple_dcp *dcp)
{
	return dcp->panel.width_mm > 0;
}

int dcp_set_crc(struct drm_crtc *crtc, bool enabled)
{
	struct apple_crtc *ac = to_apple_crtc(crtc);
	struct apple_dcp *dcp = platform_get_drvdata(ac->dcp);

	dcp->crc_enabled = enabled;

	return 0;
}

/*
 * Helper to send a DRM vblank event. We do not know how call swap_submit_dcp
 * without surfaces. To avoid timeouts in drm_atomic_helper_wait_for_vblanks
 * send a vblank event via a workqueue.
 */
static void dcp_delayed_vblank(struct work_struct *work)
{
	struct apple_dcp *dcp;

	dcp = container_of(work, struct apple_dcp, vblank_wq);
	mdelay(5);
	dcp_drm_crtc_vblank(dcp->crtc);
}

static void dcp_recv_msg(void *cookie, u8 endpoint, u64 message)
{
	struct apple_dcp *dcp = cookie;

	trace_dcp_recv_msg(dcp, endpoint, message);

	switch (endpoint) {
	case IOMFB_ENDPOINT:
		return iomfb_recv_msg(dcp, message);
	case AV_ENDPOINT:
		afk_receive_message(dcp->avep, message);
		return;
	case SYSTEM_ENDPOINT:
		afk_receive_message(dcp->systemep, message);
		return;
	case DISP0_ENDPOINT:
		afk_receive_message(dcp->ibootep, message);
		return;
	case DPAVSERV_ENDPOINT:
		afk_receive_message(dcp->dcpavservep, message);
		return;
	case DPTX_ENDPOINT:
		afk_receive_message(dcp->dptxep, message);
		return;
	default:
		WARN(endpoint, "unknown DCP endpoint %hhu\n", endpoint);
	}
}

static void dcp_rtk_crashed(void *cookie, const void *crashlog, size_t crashlog_size)
{
	struct apple_dcp *dcp = cookie;

	dcp->crashed = true;
	dev_err(dcp->dev, "DCP has crashed\n");
	/* dcp_hotplug() drops the EDID, under mode_config.mutex */
	if (dcp->connector) {
		dcp->connector->connected = 0;
		schedule_work(&dcp->connector->hotplug_wq);
	}
	complete(&dcp->start_done);
}

static int dcp_rtk_shmem_setup(void *cookie, struct apple_rtkit_shmem *bfr)
{
	struct apple_dcp *dcp = cookie;

	if (bfr->iova) {
		struct iommu_domain *domain =
			iommu_get_domain_for_dev(dcp->dev);
		phys_addr_t phy_addr;

		if (!domain)
			return -ENOMEM;

		// TODO: get map from device-tree
		phy_addr = iommu_iova_to_phys(domain, bfr->iova);
		if (!phy_addr)
			return -ENOMEM;

		// TODO: verify phy_addr, cache attribute
		bfr->buffer = memremap(phy_addr, bfr->size, MEMREMAP_WB);
		if (!bfr->buffer)
			return -ENOMEM;

		bfr->is_mapped = true;
		dev_info(dcp->dev,
			 "shmem_setup: iova: %lx -> pa: %lx -> iomem: %lx\n",
			 (uintptr_t)bfr->iova, (uintptr_t)phy_addr,
			 (uintptr_t)bfr->buffer);
	} else {
		bfr->buffer = dma_alloc_coherent(dcp->dev, bfr->size,
						 &bfr->iova, GFP_KERNEL);
		if (!bfr->buffer)
			return -ENOMEM;

		dev_info(dcp->dev, "shmem_setup: iova: %lx, buffer: %lx\n",
			 (uintptr_t)bfr->iova, (uintptr_t)bfr->buffer);
	}

	return 0;
}

static void dcp_rtk_shmem_destroy(void *cookie, struct apple_rtkit_shmem *bfr)
{
	struct apple_dcp *dcp = cookie;

	if (bfr->is_mapped)
		memunmap(bfr->buffer);
	else
		dma_free_coherent(dcp->dev, bfr->size, bfr->buffer, bfr->iova);
}

static struct apple_rtkit_ops rtkit_ops = {
	.crashed = dcp_rtk_crashed,
	.recv_message = dcp_recv_msg,
	.shmem_setup = dcp_rtk_shmem_setup,
	.shmem_destroy = dcp_rtk_shmem_destroy,
};

void dcp_send_message(struct apple_dcp *dcp, u8 endpoint, u64 message)
{
	trace_dcp_send_msg(dcp, endpoint, message);
	apple_rtkit_send_message(dcp->rtk, endpoint, message, NULL,
				 true);
}

int dcp_crtc_atomic_check(struct drm_crtc *crtc, struct drm_atomic_commit *commit)
{
	struct platform_device *pdev = to_apple_crtc(crtc)->dcp;
	struct apple_dcp *dcp = platform_get_drvdata(pdev);
	struct drm_crtc_state *crtc_state;
	bool needs_modeset;

	if (dcp->crashed)
		return -EINVAL;

	crtc_state = drm_atomic_get_new_crtc_state(commit, crtc);

	needs_modeset = drm_atomic_crtc_needs_modeset(crtc_state) || !dcp->valid_mode;
	if (!needs_modeset && !dcp->connector->connected) {
		dev_err(dcp->dev, "crtc_atomic_check: disconnected but no modeset\n");
		return -EINVAL;
	}

	return 0;
}

int dcp_get_connector_type(struct platform_device *pdev)
{
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	return (dcp->connector_type);
}

#define DPTX_CONNECT_TIMEOUT msecs_to_jiffies(2000)

static void dcp_dptx_xbar_select(struct apple_dcp *dcp)
{
	int ret;

	if (!(dcp->dptx_tunneled || dcp->switch_active) || !dcp->xbar ||
	    dcp->xbar_selected)
		return;

	ret = mux_control_select(dcp->xbar, dcp->xbar_index);
	if (ret)
		dev_warn(dcp->dev, "dp-xbar select failed: %d\n", ret);
	else
		WRITE_ONCE(dcp->xbar_selected, true);
}

static bool dcp_has_dptx(struct apple_dcp *dcp)
{
	return dcp->phy || dcp->dptx_tunneled || dcp->dp_switch;
}

static int dcp_dptx_connect(struct apple_dcp *dcp, u32 port)
{
	int ret = 0;

	if (!dcp_has_dptx(dcp)) {
		dev_warn(dcp->dev, "dcp_dptx_connect: missing phy\n");
		return -ENODEV;
	}
	dev_info(dcp->dev, "%s(port=%d)\n", __func__, port);

	mutex_lock(&dcp->hpd_mutex);
	if (!dcp->dptxport[port].enabled) {
		dev_warn(dcp->dev, "dcp_dptx_connect: dptx service for port %d not enabled\n", port);
		ret = -ENODEV;
		goto out_unlock;
	}

	if (dcp->dptxport[port].connected)
		goto out_unlock;

	reinit_completion(&dcp->dptxport[port].linkcfg_completion);
	dcp->dptxport[port].atcphy = dcp->phy;
	if (dcp->dptx_tunneled) {
		/* macOS validates the tunnelled target before connecting to it */
		ret = dptxport_validate_connection(dcp->dptxport[port].service,
						   dcp->dptx_core, dcp->dptx_phy,
						   dcp->dptx_die);
		if (ret)
			dev_warn(dcp->dev, "dptx validate_connection failed: %d\n", ret);
	}
	/* DP alt mode: the crossbar feeds the port's DP PHY before connectTo */
	if (!dcp->dptx_tunneled)
		dcp_dptx_xbar_select(dcp);
	dptxport_connect(dcp->dptxport[port].service, dcp->dptx_core,
			 dcp->dptx_phy, dcp->dptx_die);
	/*
	 * macOS routes dispext into the DP IN only after connectTo; DCP then
	 * activates the port and sees HPD.
	 */
	dcp_dptx_xbar_select(dcp);
	dptxport_request_display(dcp->dptxport[port].service);
	dcp->dptxport[port].connected = true;
	/*
	 * A tunnelled DP IN gets HPD right after DCP's ACTIVATE, before any
	 * link config, as in macOS, rather than after waiting for it.
	 */
	if (dcp->dptx_tunneled) {
		ret = dptxport_set_hpd(dcp->dptxport[port].service, true);
		if (ret)
			dev_warn(dcp->dev, "tunnelled DP IN: HPD failed: %d\n", ret);
	}

	mutex_unlock(&dcp->hpd_mutex);
	ret = wait_for_completion_timeout(&dcp->dptxport[port].linkcfg_completion,
				    DPTX_CONNECT_TIMEOUT);
	if (ret < 0)
		dev_warn(dcp->dev, "dcp_dptx_connect: port %d link complete failed:%d\n",
			 port, ret);
	else
		dev_dbg(dcp->dev, "dcp_dptx_connect: waited %d ms for link\n",
			jiffies_to_msecs(DPTX_CONNECT_TIMEOUT - ret));

	usleep_range(5, 10);

	/* a DP sink, also on a DCP whose fixed port is HDMI (GPIO HPD) */
	if ((dcp->connector_type == DRM_MODE_CONNECTOR_DisplayPort ||
	     dcp->switch_active) && !dcp->dptx_tunneled)
		dptxport_set_hpd(dcp->dptxport[port].service, true);

	if (dcp->avep)
		av_service_connect(dcp);

	return 0;

out_unlock:
	mutex_unlock(&dcp->hpd_mutex);
	return ret;
}

static void disconnected_hpd_event(struct apple_connector *con)
{
	if (con && con->connected) {
		con->connected = 0;
		drm_kms_helper_connector_hotplug_event(&con->base);
	}
}

/*
 * Drop the cached EDID when a sink goes away, so the next one is read afresh:
 * dcp_hotplug() frees it only if it still sees the disconnect, which a quick
 * disconnect and connect (a display switch handover, a replug) folds away.
 * get_modes() reads it under mode_config.mutex; not for callers that hold
 * modeset locks already.
 */
static void dcp_forget_edid(struct apple_dcp *dcp)
{
	struct apple_connector *con = dcp->connector;

	if (!con)
		return;
	mutex_lock(&con->base.dev->mode_config.mutex);
	drm_edid_free(con->drm_edid);
	con->drm_edid = NULL;
	mutex_unlock(&con->base.dev->mode_config.mutex);
}

static int dcp_dptx_disconnect(struct apple_dcp *dcp, u32 port)
{
	dev_info(dcp->dev, "%s(port=%d)\n", __func__, port);

	mutex_lock(&dcp->hpd_mutex);
	if (dcp->dptxport[port].enabled && dcp->dptxport[port].connected) {
		dptxport_release_display(dcp->dptxport[port].service);
		dcp->dptxport[port].connected = false;
	}
	if (dcp->xbar_selected) {
		mux_control_deselect(dcp->xbar);
		WRITE_ONCE(dcp->xbar_selected, false);
	}
	mutex_unlock(&dcp->hpd_mutex);

	return 0;
}

static const char *const dcp_switch_port_names[] = { "dpphy", "dpin0", "dpin1" };

static bool dcp_hdmi_connected(struct apple_dcp *dcp)
{
	return dcp->hdmi_hpd && gpiod_get_value_cansleep(dcp->hdmi_hpd);
}

/* a DCP with a fixed HDMI port serves the switch only while HDMI is empty */
bool dcp_switch_available(struct apple_dcp *dcp)
{
	return dcp->dptxport[0].enabled && !dcp->switch_active &&
	       !dcp_hdmi_connected(dcp) && !READ_ONCE(dcp->crashed) &&
	       !IS_ERR_OR_NULL(dcp->rtk) && apple_rtkit_is_running(dcp->rtk);
}

/*
 * Called by the display switch with its lock held: route this DCP to the DP
 * PHY (DP alt mode) or a DP IN (tunnel) of a Type-C port and connect to it.
 * The phy and crossbar output are taken here, not at probe: a port may be
 * missing (the m1n1 hypervisor keeps its own).
 */
int dcp_switch_connect(struct apple_dcp *dcp, u32 die, u32 atc, u32 port)
{
	char name[16];
	struct phy *phy;
	struct mux_control *xbar;

	if (port >= ARRAY_SIZE(dcp_switch_port_names))
		return -EINVAL;

	snprintf(name, sizeof(name), "atc%u", atc);
	phy = of_phy_get(dcp->dev->of_node, name);
	if (IS_ERR(phy))
		return PTR_ERR(phy);

	snprintf(name, sizeof(name), "atc%u-%s", atc, dcp_switch_port_names[port]);
	xbar = mux_control_get(dcp->dev, name);
	if (IS_ERR(xbar)) {
		of_phy_put(phy);
		return PTR_ERR(xbar);
	}

	/* put a fixed HDMI route aside; its own crossbar stays selected */
	dcp->fixed.phy = dcp->phy;
	dcp->fixed.xbar = dcp->xbar;
	dcp->fixed.dptx_phy = dcp->dptx_phy;
	dcp->fixed.dptx_core = dcp->dptx_core;
	dcp->fixed.dptx_die = dcp->dptx_die;
	dcp->switch_active = true;
	WRITE_ONCE(dcp->xbar_selected, false);

	dcp->dptx_tunneled = port != APPLE_DP_SWITCH_DPPHY;
	dcp->dptx_core = port;
	dcp->dptx_phy = atc;
	dcp->dptx_die = die;
	if (dcp->dptx_tunneled)
		dcp->tunnel_phy = phy;
	else
		dcp->phy = phy;
	dcp->xbar = xbar;

	/* a Type-C sink is DisplayPort, not the fixed port's HDMI */
	if (dcp->connector_switch) {
		if (dcp->connector_fixed->connected)
			disconnected_hpd_event(dcp->connector_fixed);
		dcp->connector = dcp->connector_switch;
	}

	return dcp_dptx_connect(dcp, 0);
}

/*
 * teardown: the DCP is being unbound or removed, so a fixed HDMI sink waits
 * for the next bind instead of being connected (and waited for) here.
 */
void dcp_switch_disconnect(struct apple_dcp *dcp, bool teardown)
{
	struct phy *phy = dcp->dptx_tunneled ? dcp->tunnel_phy : dcp->phy;

	if (!dcp->switch_active)
		return;

	disconnected_hpd_event(dcp->connector);
	dcp_forget_edid(dcp);
	if (dcp->avep)
		av_service_disconnect(dcp);
	if (dcp->dptxport[0].enabled && dcp->dptxport[0].connected)
		dptxport_set_hpd(dcp->dptxport[0].service, false);
	dcp_dptx_disconnect(dcp, 0);

	/* stop the tunnel's pixel clock in case DCP left it running */
	if (dcp->dptx_tunneled && dcp->tunnel_phy)
		apple_atc_dp_tunnel_rate(dcp->tunnel_phy, dcp->dptx_core - 1, 0);

	mux_control_put(dcp->xbar);
	of_phy_put(phy);
	dcp->tunnel_phy = NULL;
	dcp->dptx_tunneled = false;
	dcp->dptxport[0].atcphy = NULL;

	dcp->phy = dcp->fixed.phy;
	dcp->xbar = dcp->fixed.xbar;
	dcp->dptx_phy = dcp->fixed.dptx_phy;
	dcp->dptx_core = dcp->fixed.dptx_core;
	dcp->dptx_die = dcp->fixed.dptx_die;
	dcp->switch_active = false;
	if (dcp->connector_switch)
		dcp->connector = dcp->connector_fixed;

	/*
	 * The dispext side of a crossbar route (its FIFO write enables) is
	 * shared by every port's crossbar, so releasing the switched route just
	 * turned off what the fixed one still needs: route it again.
	 */
	if (dcp->xbar) {
		int ret;

		if (dcp->fixed_xbar_selected)
			mux_control_deselect(dcp->xbar);
		ret = mux_control_select(dcp->xbar, dcp->xbar_index);
		if (ret)
			dev_warn(dcp->dev, "dp-switch: fixed route reselect failed: %d\n",
				 ret);
		dcp->fixed_xbar_selected = !ret;
	}

	/* HDMI plugged in while the switch had this DCP */
	if (!teardown && dcp_hdmi_connected(dcp))
		dcp_dptx_connect(dcp, 0);
}

int dcp_dptx_connect_oob(struct platform_device *pdev, u32 port)
{
	struct apple_dcp *dcp = platform_get_drvdata(pdev);
	return dcp_dptx_connect(dcp, port);
}

int dcp_dptx_disconnect_oob(struct platform_device *pdev, u32 port)
{
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	disconnected_hpd_event(dcp->connector);
	dcp_forget_edid(dcp);

	if (dcp->avep)
		av_service_disconnect(dcp);

	if (dcp->dptxport[port].enabled)
		dptxport_set_hpd(dcp->dptxport[port].service, false);

	return dcp_dptx_disconnect(dcp, port);
}

static irqreturn_t dcp_dp2hdmi_hpd(int irq, void *data)
{
	struct apple_dcp *dcp = data;
	bool connected = gpiod_get_value_cansleep(dcp->hdmi_hpd);

	/* do nothing on disconnect and trust that dcp detects it itself.
	 * Parallel disconnect HPDs result drm disabling the CRTC even when it
	 * should not.
	 * The interrupt should be changed to rising but for now the disconnect
	 * IRQs might be helpful for debugging.
	 */
	dev_info(dcp->dev, "DP2HDMI HPD irq, connected:%d\n", connected);

	if (connected) {
		msleep(500);
		connected = gpiod_get_value_cansleep(dcp->hdmi_hpd);
		dev_info(dcp->dev, "DP2HDMI HPD irq, 500ms debounce: connected:%d\n", connected);
	}

	if (connected && !dcp->switch_active)
		dcp_dptx_connect(dcp, 0);
	else if (!connected && !dcp->switch_active)
		/* the HDMI port let go of this DCP: the switch may use it */
		dp_switch_kick();

	return IRQ_HANDLED;
}

void dcp_link(struct platform_device *pdev, struct apple_crtc *crtc,
	      struct apple_connector *connector)
{
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	dcp->crtc = crtc;
	dcp->connector = connector;
}

/* a switch member whose own connector is typed for its fixed HDMI port */
bool dcp_wants_switch_connector(struct platform_device *pdev)
{
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	return dcp->dp_switch && dcp->connector_type == DRM_MODE_CONNECTOR_HDMIA;
}

/*
 * Copy the ELD of the connector the sink is on now (the display switch may
 * have moved the DCP to its other connector) for the audio side. Returns the
 * number of bytes, 0 without a sink or without audio in its EDID.
 */
int dcp_get_eld(struct device *dev, u8 *buf, size_t size)
{
	struct apple_dcp *dcp = dev_get_drvdata(dev);
	struct drm_connector *connector;
	int len = 0;

	if (!dcp->connector)
		return 0;
	connector = &dcp->connector->base;

	mutex_lock(&connector->eld_mutex);
	if (dcp->connector->connected && connector->eld[DRM_ELD_BASELINE_ELD_LEN]) {
		len = min_t(size_t, drm_eld_size(connector->eld), size);
		memcpy(buf, connector->eld, len);
	}
	mutex_unlock(&connector->eld_mutex);

	return len;
}

/* which of a DCP's connectors the sink is on; the other one cannot be used */
bool dcp_connector_is_current(struct platform_device *pdev,
			      struct apple_connector *connector)
{
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	return !dcp->connector_switch || dcp->connector == connector;
}

void dcp_link_switch_connector(struct platform_device *pdev,
			       struct apple_connector *connector)
{
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	dcp->connector_fixed = dcp->connector;
	dcp->connector_switch = connector;
	/* the switch may have routed a sink before the connectors existed */
	if (dcp->switch_active)
		dcp->connector = connector;
}


bool dcp_fw_compat_is_12_x(struct platform_device *pdev)
{
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	return dcp->fw_compat == DCP_FIRMWARE_V_12_3;
}

unsigned long* dcp_get_iomfb_surfaces(struct platform_device *pdev)
{
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	return dcp->iomfb_surfaces;
}

int dcp_start(struct platform_device *pdev)
{
	struct apple_dcp *dcp = platform_get_drvdata(pdev);
	int ret;

	if (IS_ERR_OR_NULL(dcp->rtk))
		return -ENODEV;

	init_completion(&dcp->start_done);

	/* start RTKit endpoints */
	ret = systemep_init(dcp);
	if (ret)
		dev_warn(dcp->dev, "Failed to start system endpoint: %d\n", ret);

	if (unstable_edid && !dcp_has_panel(dcp)) {
		ret = dpavservep_init(dcp);
		if (ret)
			dev_warn(dcp->dev, "Failed to start DPAVSERV endpoint: %d",
				 ret);
	}

	if (dcp_has_dptx(dcp) && dcp->fw_compat >= DCP_FIRMWARE_V_13_5) {
		ret = ibootep_init(dcp);
		if (ret)
			dev_warn(dcp->dev, "Failed to start IBOOT endpoint: %d\n",
				 ret);

		ret = dptxep_init(dcp);
		if (ret) {
			dev_warn(dcp->dev, "Failed to start DPTX endpoint: %d\n",
				 ret);
#ifdef DCP_DPTX_DISCONNECT_ON_INIT
		/*
		 * This disconnect / connect cycle on init is only necessary
		 * when using dcp0 on j473, j474s and presumedly j475c.
		 * Since dcp0 is not used at the moment let's avoid this
		 * since it is possibly the cause for startup issues.
		 */
		} else if (dcp->dptxport[0].enabled) {
			bool connected;
			/* force disconnect on start - necessary if the display
			 * is already up from m1n1
			 */
			dptxport_set_hpd(dcp->dptxport[0].service, false);
			dptxport_release_display(dcp->dptxport[0].service);
			usleep_range(10 * USEC_PER_MSEC, 25 * USEC_PER_MSEC);

			connected = gpiod_get_value_cansleep(dcp->hdmi_hpd);
			dev_info(dcp->dev, "%s: DP2HDMI HPD connected:%d\n", __func__, connected);

			// necessary on j473/j474 but not on j314c
			if (connected)
				dcp_dptx_connect(dcp, 0);
#endif
		}
	} else if (dcp_has_dptx(dcp)) {
		dev_warn(dcp->dev, "OS firmware incompatible with dptxport EP\n");
	}
	ret = iomfb_start_rtkit(dcp);
	if (ret)
		dev_err(dcp->dev, "Failed to start IOMFB endpoint: %d\n", ret);

#if IS_ENABLED(CONFIG_DRM_APPLE_AUDIO)
	if (hdmi_audio) {
		ret = avep_init(dcp);
		if (ret)
			dev_warn(dcp->dev, "Failed to start AV endpoint: %d", ret);
		ret = 0;
	}
#endif

	return ret;
}

static void _dcp_poweroff(struct apple_dcp *dcp)
{
	switch (dcp->fw_compat) {
	case DCP_FIRMWARE_V_12_3:
		iomfb_poweroff_v12_3(dcp);
		break;
	case DCP_FIRMWARE_V_13_5:
		iomfb_poweroff_v13_3(dcp);
		break;
	case DCP_FIRMWARE_V_14_7:
		iomfb_poweroff_v14_7_0(dcp);
		break;
	default:
		WARN_ONCE(true, "Unexpected firmware version: %u\n", dcp->fw_compat);
		break;
	}
}

static int dcp_enable_dp2hdmi_hpd(struct apple_dcp *dcp)
{
	// check HPD state before enabling the edge triggered IRQ
	if (dcp->hdmi_hpd && !dcp->switch_active) {
		bool connected = gpiod_get_value_cansleep(dcp->hdmi_hpd);
		dev_info(dcp->dev, "%s: DP2HDMI HPD connected:%d\n", __func__, connected);

		if (connected)
			dcp_dptx_connect(dcp, 0);
		else
			_dcp_poweroff(dcp);
	}

	if (dcp->hdmi_hpd_irq)
		enable_irq(dcp->hdmi_hpd_irq);

	return 0;
}

int dcp_wait_ready(struct platform_device *pdev, u64 timeout)
{
	struct apple_dcp *dcp = platform_get_drvdata(pdev);
	int ret;

	if (dcp->crashed)
		return -ENODEV;
	if (dcp->active)
		return dcp_enable_dp2hdmi_hpd(dcp);
	if (timeout <= 0)
		return -ETIMEDOUT;

	ret = wait_for_completion_timeout(&dcp->start_done, timeout);
	if (ret < 0)
		return ret;

	if (dcp->crashed)
		return -ENODEV;

	if (dcp->active)
		dcp_enable_dp2hdmi_hpd(dcp);

	return dcp->active ? 0 : -ETIMEDOUT;
}

static void __maybe_unused dcp_sleep(struct apple_dcp *dcp)
{
	switch (dcp->fw_compat) {
	case DCP_FIRMWARE_V_12_3:
		iomfb_sleep_v12_3(dcp);
		break;
	case DCP_FIRMWARE_V_13_5:
		iomfb_sleep_v13_3(dcp);
		break;
	case DCP_FIRMWARE_V_14_7:
		iomfb_sleep_v14_7_0(dcp);
		break;
	default:
		WARN_ONCE(true, "Unexpected firmware version: %u\n", dcp->fw_compat);
		break;
	}
}

void dcp_poweron(struct platform_device *pdev)
{
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	if (dcp->hdmi_hpd && !dcp->switch_active) {
		bool connected = gpiod_get_value_cansleep(dcp->hdmi_hpd);
		dev_info(dcp->dev, "%s: DP2HDMI HPD connected:%d\n", __func__, connected);

		if (connected)
			dcp_dptx_connect(dcp, 0);
	}

	switch (dcp->fw_compat) {
	case DCP_FIRMWARE_V_12_3:
		iomfb_poweron_v12_3(dcp);
		break;
	case DCP_FIRMWARE_V_13_5:
		iomfb_poweron_v13_3(dcp);
		break;
	case DCP_FIRMWARE_V_14_7:
		iomfb_poweron_v14_7_0(dcp);
		break;
	default:
		WARN_ONCE(true, "Unexpected firmware version: %u\n", dcp->fw_compat);
		break;
	}

	/*
	 * Only with a sink: the display switch may have released this DCP's
	 * route while the modeset that powers it on was under way.
	 */
	if (dcp->avep && dcp->dptxport[0].connected)
		av_service_connect(dcp);
}

void dcp_poweroff(struct platform_device *pdev)
{
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	if (dcp->avep)
		av_service_disconnect(dcp);

	_dcp_poweroff(dcp);

	if (dcp->hdmi_hpd && !dcp->switch_active) {
		bool connected = gpiod_get_value_cansleep(dcp->hdmi_hpd);
		if (!connected) {
			disconnected_hpd_event(dcp->connector);
			dcp_dptx_disconnect(dcp, 0);
		}
	}
}

static void dcp_work_register_backlight(struct work_struct *work)
{
	int ret;
	struct apple_dcp *dcp;

	dcp = container_of(work, struct apple_dcp, bl_register_wq);

	mutex_lock(&dcp->bl_register_mutex);
	if (dcp->brightness.bl_dev)
		goto out_unlock;

	/* try to register backlight device, */
	ret = dcp_backlight_register(dcp);
	if (ret) {
		dev_err(dcp->dev, "Unable to register backlight device\n");
		dcp->brightness.maximum = 0;
	}

out_unlock:
	mutex_unlock(&dcp->bl_register_mutex);
}

static void dcp_work_update_backlight(struct work_struct *work)
{
	struct apple_dcp *dcp;

	dcp = container_of(work, struct apple_dcp, bl_update_wq);

	dcp_backlight_update(dcp);
}

static int dcp_create_piodma_iommu_dev(struct apple_dcp *dcp)
{
	int ret;
	struct device_node *node __free(device_node) = of_get_child_by_name(dcp->dev->of_node, "piodma");

	if (!node)
		return dev_err_probe(dcp->dev, -ENODEV,
				     "Failed to get piodma child DT node\n");

	dcp->piodma = of_platform_device_create(node, NULL, dcp->dev);
	if (!dcp->piodma)
		return dev_err_probe(dcp->dev, -ENODEV, "Failed to create piodma pdev for %pOF\n", node);

	ret = dma_set_mask_and_coherent(&dcp->piodma->dev, DMA_BIT_MASK(42));
	if (ret)
		goto err_destroy_pdev;

	ret = of_dma_configure(&dcp->piodma->dev, node, true);
	if (ret) {
		ret = dev_err_probe(dcp->dev, ret,
			"Failed to configure IOMMU child DMA\n");
		goto err_destroy_pdev;
	}

	dcp->iommu_dom = iommu_get_domain_for_dev(&dcp->piodma->dev);
	if (!dcp->iommu_dom) {
		ret = -EPROBE_DEFER;
		goto err_destroy_pdev;
	}

	return 0;
err_destroy_pdev:
	of_platform_device_destroy(&dcp->piodma->dev, NULL);
	dcp->piodma = NULL;
	return ret;
}

static int dcp_get_bw_scratch_reg(struct apple_dcp *dcp, u32 expected)
{
	struct of_phandle_args ph_args;
	u32 addr_idx, disp_idx, offset;
	int ret;

	ret = of_parse_phandle_with_args(dcp->dev->of_node, "apple,bw-scratch",
				   "#apple,bw-scratch-cells", 0, &ph_args);
	if (ret < 0) {
		dev_err(dcp->dev, "Failed to read 'apple,bw-scratch': %d\n", ret);
		return ret;
	}

	if (ph_args.args_count != 3) {
		dev_err(dcp->dev, "Unexpected 'apple,bw-scratch' arg count %d\n",
			ph_args.args_count);
		ret = -EINVAL;
		goto err_of_node_put;
	}

	addr_idx = ph_args.args[0];
	disp_idx = ph_args.args[1];
	offset = ph_args.args[2];

	if (disp_idx != expected || disp_idx >= MAX_DISP_REGISTERS) {
		dev_err(dcp->dev, "Unexpected disp_reg value in 'apple,bw-scratch': %d\n",
			disp_idx);
		ret = -EINVAL;
		goto err_of_node_put;
	}

	ret = of_address_to_resource(ph_args.np, addr_idx, &dcp->disp_bw_scratch_res);
	if (ret < 0) {
		dev_err(dcp->dev, "Failed to get 'apple,bw-scratch' resource %d from %pOF\n",
			addr_idx, ph_args.np);
		goto err_of_node_put;
	}
	if (offset > resource_size(&dcp->disp_bw_scratch_res) - 4) {
		ret = -EINVAL;
		goto err_of_node_put;
	}

	dcp->disp_registers[disp_idx] = &dcp->disp_bw_scratch_res;
	dcp->disp_bw_scratch_index = disp_idx;
	dcp->disp_bw_scratch_offset = offset;
	ret = 0;

err_of_node_put:
	of_node_put(ph_args.np);
	return ret;
}

static int dcp_get_bw_doorbell_reg(struct apple_dcp *dcp, u32 expected)
{
	struct of_phandle_args ph_args;
	u32 addr_idx, disp_idx;
	int ret;

	ret = of_parse_phandle_with_args(dcp->dev->of_node, "apple,bw-doorbell",
				   "#apple,bw-doorbell-cells", 0, &ph_args);
	if (ret < 0) {
		dev_err(dcp->dev, "Failed to read 'apple,bw-doorbell': %d\n", ret);
		return ret;
	}

	if (ph_args.args_count != 2) {
		dev_err(dcp->dev, "Unexpected 'apple,bw-doorbell' arg count %d\n",
			ph_args.args_count);
		ret = -EINVAL;
		goto err_of_node_put;
	}

	addr_idx = ph_args.args[0];
	disp_idx = ph_args.args[1];

	if (disp_idx != expected || disp_idx >= MAX_DISP_REGISTERS) {
		dev_err(dcp->dev, "Unexpected disp_reg value in 'apple,bw-doorbell': %d\n",
			disp_idx);
		ret = -EINVAL;
		goto err_of_node_put;
	}

	ret = of_address_to_resource(ph_args.np, addr_idx, &dcp->disp_bw_doorbell_res);
	if (ret < 0) {
		dev_err(dcp->dev, "Failed to get 'apple,bw-doorbell' resource %d from %pOF\n",
			addr_idx, ph_args.np);
		goto err_of_node_put;
	}
	dcp->disp_bw_doorbell_index = disp_idx;
	dcp->disp_registers[disp_idx] = &dcp->disp_bw_doorbell_res;
	ret = 0;

err_of_node_put:
	of_node_put(ph_args.np);
	return ret;
}

static int dcp_get_disp_regs(struct apple_dcp *dcp)
{
	struct platform_device *pdev = to_platform_device(dcp->dev);
	int count = pdev->num_resources - 1;
	int i, ret;

	if (count <= 0 || count > MAX_DISP_REGISTERS)
		return -EINVAL;

	for (i = 0; i < count; ++i) {
		dcp->disp_registers[i] =
			platform_get_resource(pdev, IORESOURCE_MEM, 1 + i);
	}

	/* load pmgr bandwidth scratch resource and offset */
	ret = dcp_get_bw_scratch_reg(dcp, count);
	if (ret < 0)
		return ret;
	count += 1;

	/* load pmgr bandwidth doorbell resource if present (only on t8103) */
	if (of_property_present(dcp->dev->of_node, "apple,bw-doorbell")) {
		ret = dcp_get_bw_doorbell_reg(dcp, count);
		if (ret < 0)
			return ret;
		count += 1;
	}

	dcp->nr_disp_registers = count;
	return 0;
}

#define DCP_FW_VERSION_MIN_LEN	3
#define DCP_FW_VERSION_MAX_LEN	5
#define DCP_FW_VERSION_STR_LEN	(DCP_FW_VERSION_MAX_LEN * 4)

static int dcp_read_fw_version(struct device *dev, const char *name,
			       char *version_str)
{
	u32 ver[DCP_FW_VERSION_MAX_LEN];
	int len_str;
	int len;

	len = of_property_read_variable_u32_array(dev->of_node, name, ver,
						  DCP_FW_VERSION_MIN_LEN,
						  DCP_FW_VERSION_MAX_LEN);

	switch (len) {
	case 3:
		len_str = scnprintf(version_str, DCP_FW_VERSION_STR_LEN,
				    "%d.%d.%d", ver[0], ver[1], ver[2]);
		break;
	case 4:
		len_str = scnprintf(version_str, DCP_FW_VERSION_STR_LEN,
				    "%d.%d.%d.%d", ver[0], ver[1], ver[2],
				    ver[3]);
		break;
	case 5:
		len_str = scnprintf(version_str, DCP_FW_VERSION_STR_LEN,
				    "%d.%d.%d.%d.%d", ver[0], ver[1], ver[2],
				    ver[3], ver[4]);
		break;
	default:
		len_str = strscpy(version_str, "UNKNOWN",
				  DCP_FW_VERSION_STR_LEN);
		if (len >= 0)
			len = -EOVERFLOW;
		break;
	}

	if (len_str >= DCP_FW_VERSION_STR_LEN)
		dev_warn(dev, "'%s' truncated: '%s'\n", name, version_str);

	return len;
}

static enum dcp_firmware_version dcp_check_firmware_version(struct device *dev)
{
	char compat_str[DCP_FW_VERSION_STR_LEN];
	char fw_str[DCP_FW_VERSION_STR_LEN];
	int ret;

	/* firmware version is just informative */
	dcp_read_fw_version(dev, "apple,firmware-version", fw_str);

	ret = dcp_read_fw_version(dev, "apple,firmware-compat", compat_str);
	if (ret < 0) {
		dev_err(dev, "Could not read 'apple,firmware-compat': %d\n", ret);
		return DCP_FIRMWARE_UNKNOWN;
	}

	if (strncmp(compat_str, "12.3.0", sizeof(compat_str)) == 0)
		return DCP_FIRMWARE_V_12_3;
	/*
	 * m1n1 reports firmware version 13.5 as compatible with 13.3. This is
	 * only true for the iomfb endpoint. The interface for the dptx-port
	 * endpoint changed between 13.3 and 13.5. The driver will only support
	 * firmware 13.5. Check the actual firmware version for compat version
	 * 13.3 until m1n1 reports 13.5 as "firmware-compat".
	 */
	else if ((strncmp(compat_str, "13.3.0", sizeof(compat_str)) == 0) &&
		 (strncmp(fw_str, "13.5.0", sizeof(compat_str)) == 0))
		return DCP_FIRMWARE_V_13_5;
	else if (strncmp(compat_str, "13.5.0", sizeof(compat_str)) == 0)
		return DCP_FIRMWARE_V_13_5;
	else if (strncmp(compat_str, "14.7.0", sizeof(compat_str)) == 0)
		return DCP_FIRMWARE_V_14_7;

	dev_err(dev, "DCP firmware-compat %s (FW: %s) is not supported\n",
		compat_str, fw_str);

	return DCP_FIRMWARE_UNKNOWN;
}

static void dcp_dcpext_sleep_register(struct apple_dcp *dcp, bool on);

static int dcp_comp_bind(struct device *dev, struct device *main, void *data)
{
	struct device_node *panel_np;
	struct apple_dcp *dcp = dev_get_drvdata(dev);
	u32 cpu_ctrl;
	int ret;

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(42));
	if (ret)
		return ret;

	dcp->coproc_reg = devm_platform_ioremap_resource_byname(to_platform_device(dev), "coproc");
	if (IS_ERR(dcp->coproc_reg))
		return PTR_ERR(dcp->coproc_reg);

	of_property_read_u32(dev->of_node, "apple,dcp-index",
					   &dcp->index);
	of_property_read_u32(dev->of_node, "apple,dptx-phy",
					   &dcp->dptx_phy);
	of_property_read_u32(dev->of_node, "apple,dptx-die",
					   &dcp->dptx_die);
	of_property_read_u32(dev->of_node, "apple,dptx-core",
					   &dcp->dptx_core);
	if (dcp->index || dcp->dptx_phy || dcp->dptx_die)
		dev_info(dev, "DCP index:%u dptx target phy: %u dptx die: %u core: %u%s\n",
			 dcp->index, dcp->dptx_phy, dcp->dptx_die, dcp->dptx_core,
			 dcp->dptx_tunneled ? " (tunnelled)" : "");
	mutex_init(&dcp->hpd_mutex);

	if (!show_notch)
		ret = of_property_read_u32(dev->of_node, "apple,notch-height",
					   &dcp->notch_height);

	if (dcp->notch_height > MAX_NOTCH_HEIGHT)
		dcp->notch_height = MAX_NOTCH_HEIGHT;
	if (dcp->notch_height > 0)
		dev_info(dev, "Detected display with notch of %u pixel\n", dcp->notch_height);

	/* initialize brightness scale to a sensible default to avoid divide by 0*/
	dcp->brightness.scale = 65536;
	panel_np = of_get_compatible_child(dev->of_node, "apple,panel-mini-led");
	if (panel_np)
		dcp->panel.has_mini_led = true;
	else
		panel_np = of_get_compatible_child(dev->of_node, "apple,panel");

	if (panel_np) {
		const char height_prop[2][16] = { "adj-height-mm", "height-mm" };

		if (of_device_is_available(panel_np)) {
			ret = of_property_read_u32(panel_np, "apple,max-brightness",
						   &dcp->brightness.maximum);
			if (ret)
				dev_err(dev, "Missing property 'apple,max-brightness'\n");
		}

		of_property_read_u32(panel_np, "width-mm", &dcp->panel.width_mm);
		/* use adjusted height as long as the notch is hidden */
		of_property_read_u32(panel_np, height_prop[!dcp->notch_height],
				     &dcp->panel.height_mm);

		of_node_put(panel_np);
		dcp->connector_type = DRM_MODE_CONNECTOR_eDP;
		INIT_WORK(&dcp->bl_register_wq, dcp_work_register_backlight);
		mutex_init(&dcp->bl_register_mutex);
		INIT_WORK(&dcp->bl_update_wq, dcp_work_update_backlight);
	} else if (of_property_match_string(dev->of_node, "apple,connector-type", "HDMI-A") >= 0)
		dcp->connector_type = DRM_MODE_CONNECTOR_HDMIA;
	else if (of_property_match_string(dev->of_node, "apple,connector-type", "DP") >= 0)
		dcp->connector_type = DRM_MODE_CONNECTOR_DisplayPort;
	else if (of_property_match_string(dev->of_node, "apple,connector-type", "USB-C") >= 0)
		dcp->connector_type = DRM_MODE_CONNECTOR_USB;
	else
		dcp->connector_type = DRM_MODE_CONNECTOR_Unknown;

	ret = dcp_get_disp_regs(dcp);
	if (ret) {
		dev_err(dev, "failed to find display registers\n");
		return ret;
	}

	dcp->clk = devm_clk_get(dev, NULL);
	if (IS_ERR(dcp->clk))
		return dev_err_probe(dev, PTR_ERR(dcp->clk),
				     "Unable to find clock\n");

	bitmap_zero(dcp->memdesc_map, DCP_MAX_MAPPINGS);
	// TDOD: mem_desc IDs start at 1, for simplicity just skip '0' entry
	set_bit(0, dcp->memdesc_map);

	INIT_WORK(&dcp->vblank_wq, dcp_delayed_vblank);

	dcp->swapped_out_fbs =
		(struct list_head)LIST_HEAD_INIT(dcp->swapped_out_fbs);

	cpu_ctrl =
		readl_relaxed(dcp->coproc_reg + APPLE_DCP_COPROC_CPU_CONTROL);
	writel_relaxed(cpu_ctrl | APPLE_DCP_COPROC_CPU_CONTROL_RUN,
		       dcp->coproc_reg + APPLE_DCP_COPROC_CPU_CONTROL);

	dcp->rtk = devm_apple_rtkit_init(dev, dcp, "mbox", 0, &rtkit_ops);
	if (IS_ERR(dcp->rtk))
		return dev_err_probe(dev, PTR_ERR(dcp->rtk),
				     "Failed to initialize RTKit\n");

	ret = apple_rtkit_wake(dcp->rtk);
	if (ret)
		return dev_err_probe(dev, ret,
				     "Failed to boot RTKit: %d\n", ret);
	/* An external one: sleep-seq asks at each S2R's .begin whether it will stop */
	dcp_dcpext_sleep_register(dcp, true);
	return ret;
}

static void destroy_piodma_device(struct apple_dcp *dcp)
{
	if (dcp->piodma) {
		of_platform_device_destroy(&dcp->piodma->dev, NULL);
		dcp->piodma = NULL;
	}
}

/*
 * We need to shutdown DCP before tearing down the display subsystem. Otherwise
 * the DCP will crash and briefly flash a green screen of death.
 */
static void dcp_comp_unbind(struct device *dev, struct device *main, void *data)
{
	struct apple_dcp *dcp = dev_get_drvdata(dev);

	if (!dcp)
		return;

	dcp_dcpext_sleep_register(dcp, false);
	if (dcp->hdmi_hpd_irq)
		disable_irq(dcp->hdmi_hpd_irq);
	/* No stale "down" for sleep-seq (rv-usb4) */
	if (dcp->dcpext_stopped) {
		dcp->dcpext_stopped = false;
		apple_sleep_dispext_down(dev, false);
	}

	/* the DRM device and its connectors go away after this unbind */
	if (dcp->dp_switch)
		dp_switch_unbind_dcp(dcp);

	typec_mux_put(dcp->typec_mux);

	if (dcp->avep) {
		av_service_disconnect(dcp);
		afk_shutdown(dcp->avep);
		dcp->avep = NULL;
	}

	if (dcp->dptxep) {
		afk_shutdown(dcp->dptxep);
		dcp->dptxep = NULL;
	}

	if (dcp->ibootep) {
		afk_shutdown(dcp->ibootep);
		dcp->ibootep = NULL;
	}

	if (dcp->systemep) {
		afk_shutdown(dcp->systemep);
		dcp->systemep = NULL;
	}

	if (dcp->dcpavservep) {
		afk_shutdown(dcp->dcpavservep);
		dcp->dcpavservep = NULL;
	}

	if (dcp->shmem)
		iomfb_shutdown(dcp);

	if (dcp->connector_type == DRM_MODE_CONNECTOR_eDP) {
		if (dcp->bl_register_wq.func)
			cancel_work_sync(&dcp->bl_register_wq);
		if (dcp->bl_update_wq.func)
			cancel_work_sync(&dcp->bl_update_wq);
	}
	if (dcp->vblank_wq.func)
		cancel_work_sync(&dcp->vblank_wq);

	if (dcp->clk) {
		devm_clk_put(dev, dcp->clk);
		dcp->clk = NULL;
	}

	/*
	 * the next bind links new ones and brings the DPTX ports up afresh; a
	 * pending dcp_hotplug() must not outlive the connector
	 */
	if (dcp->connector)
		cancel_work_sync(&dcp->connector->hotplug_wq);
	if (dcp->connector_fixed)
		cancel_work_sync(&dcp->connector_fixed->hotplug_wq);
	if (dcp->connector_switch)
		cancel_work_sync(&dcp->connector_switch->hotplug_wq);
	dcp->connector = NULL;
	dcp->connector_fixed = NULL;
	dcp->connector_switch = NULL;
	for (int i = 0; i < ARRAY_SIZE(dcp->dptxport); i++) {
		dcp->dptxport[i].enabled = false;
		dcp->dptxport[i].connected = false;
	}
}

static const struct component_ops dcp_comp_ops = {
	.bind	= dcp_comp_bind,
	.unbind	= dcp_comp_unbind,
};

static void dcp_leave_switch(void *data)
{
	dp_switch_remove_dcp(data);
}

/* the crossbar outlives appledrm: a route left selected blocks the next probe */
static void dcp_deselect_fixed_xbar(void *data)
{
	struct apple_dcp *dcp = data;

	if (dcp->fixed_xbar_selected)
		mux_control_deselect(dcp->fixed_xbar);
	dcp->fixed_xbar_selected = false;
}

static int dcp_platform_probe(struct platform_device *pdev)
{
	enum dcp_firmware_version fw_compat;
	struct device *dev = &pdev->dev;
	struct apple_dcp *dcp;
	int ret, surf, num_surfs;
	u32 surf_en;
	u32 mux_index;

	fw_compat = dcp_check_firmware_version(dev);
	if (fw_compat == DCP_FIRMWARE_UNKNOWN)
		return -ENODEV;

	/* Check for "apple,bw-scratch" to avoid probing appledrm with outdated
	 * device trees. This prevents replacing simpledrm and ending up without
	 * display.
	 */
	if (!of_property_present(dev->of_node, "apple,bw-scratch"))
		return dev_err_probe(dev, -ENODEV, "Incompatible devicetree! "
			"Use devicetree matching this kernel.\n");

	dcp = devm_kzalloc(dev, sizeof(*dcp), GFP_KERNEL);
	if (!dcp)
		return -ENOMEM;

	dcp->fw_compat = fw_compat;
	dcp->dev = dev;
	dcp->hw = *(struct apple_dcp_hw_data *)of_device_get_match_data(dev);

	platform_set_drvdata(pdev, dcp);

	ret = dcp_create_piodma_iommu_dev(dcp);
	if (ret < 0)
		return dev_err_probe(dev, ret,
				"Failed to created PIODMA iommu child device");

	dcp->phy = devm_phy_optional_get(dev, "dp-phy");
	if (IS_ERR(dcp->phy)) {
		dev_err(dev, "Failed to get dp-phy: %ld\n", PTR_ERR(dcp->phy));
		return PTR_ERR(dcp->phy);
	}
	/* a tunnelled DP IN's pixel clock comes from its port's ATC PHY */
	dcp->tunnel_phy = devm_phy_optional_get(dev, "tunnel-phy");
	if (IS_ERR(dcp->tunnel_phy))
		return dev_err_probe(dev, PTR_ERR(dcp->tunnel_phy),
				     "Failed to get tunnel-phy\n");

	bitmap_zero(dcp->iomfb_surfaces, DCP_MAX_PLANES);
	if (!of_property_present(dev->of_node, "apple,iomfb-surfaces"))
		num_surfs = 0;
	else
		num_surfs = of_property_count_elems_of_size(dev->of_node,
						    "apple,iomfb-surfaces",
						    sizeof(u32));

	if (num_surfs == 0 || num_surfs == -ENODATA) {
		set_bit(0, dcp->iomfb_surfaces);
		set_bit(1, dcp->iomfb_surfaces);
	} else if (num_surfs < 0) {
		return num_surfs;
	} else if (num_surfs > DCP_MAX_PLANES) {
		dev_err(dev, "Number of iomfb-surfaces (%d) exceeds DCP_MAX_PLANES\n",
			num_surfs);
		return -EINVAL;
	}

	surf = 0;
	of_property_for_each_u32(dev->of_node, "apple,iomfb-surfaces", surf_en) {
		if (surf_en)
			set_bit(surf, dcp->iomfb_surfaces);
		surf++;
	}

	dcp->dptx_tunneled = of_property_read_bool(dev->of_node,
						   "apple,dptx-tunneled");
	dcp->dp_switch = of_property_read_bool(dev->of_node, "apple,dp-switch");
	if (dcp->dp_switch) {
		if (of_property_read_u32(dev->of_node, "mux-index", &dcp->xbar_index))
			return dev_err_probe(dev, -EINVAL,
					     "dp-switch DCP without mux-index\n");
	}
	/* selected after connectTo, see dcp_dptx_connect() */
	if (dcp->dptx_tunneled &&
	    !of_property_read_u32(dev->of_node, "mux-index", &dcp->xbar_index)) {
		dcp->xbar = devm_mux_control_get(dev, "dp-xbar");
		if (IS_ERR(dcp->xbar))
			return dev_err_probe(dev, PTR_ERR(dcp->xbar),
					     "Failed to get dp-xbar\n");
	}

	if (dcp->phy) {
		int ret;
		/*
		 * Request DP2HDMI related GPIOs as optional for DP-altmode
		 * compatibility. J180D misses a dp2hdmi-pwren GPIO in the
		 * template ADT. TODO: check device ADT
		 */
		dcp->hdmi_hpd = devm_gpiod_get_optional(dev, "hdmi-hpd", GPIOD_IN);
		if (IS_ERR(dcp->hdmi_hpd))
			return PTR_ERR(dcp->hdmi_hpd);
		if (dcp->hdmi_hpd) {
			int irq = gpiod_to_irq(dcp->hdmi_hpd);
			if (irq < 0) {
				dev_err(dev, "failed to translate HDMI hpd GPIO to IRQ\n");
				return irq;
			}
			dcp->hdmi_hpd_irq = irq;

			ret = devm_request_threaded_irq(dev, dcp->hdmi_hpd_irq,
						NULL, dcp_dp2hdmi_hpd,
						IRQF_ONESHOT | IRQF_NO_AUTOEN |
						IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING,
						"dp2hdmi-hpd-irq", dcp);
			if (ret < 0) {
				dev_err(dev, "failed to request HDMI hpd irq %d: %d\n",
					irq, ret);
				return ret;
			}
		}

		/*
		 * Power DP2HDMI on as it is required for the HPD irq.
		 * TODO: check if one is sufficient for the hpd to save power
		 *       on battery powered Macbooks.
		 */
		dcp->hdmi_pwren = devm_gpiod_get_optional(dev, "hdmi-pwren", GPIOD_OUT_HIGH);
		if (IS_ERR(dcp->hdmi_pwren))
			return PTR_ERR(dcp->hdmi_pwren);

		dcp->dp2hdmi_pwren = devm_gpiod_get_optional(dev, "dp2hdmi-pwren", GPIOD_OUT_HIGH);
		if (IS_ERR(dcp->dp2hdmi_pwren))
			return PTR_ERR(dcp->dp2hdmi_pwren);

		ret = of_property_read_u32(dev->of_node, "mux-index", &mux_index);
		if (!ret) {
			dcp->xbar = devm_mux_control_get(dev, "dp-xbar");
			if (IS_ERR(dcp->xbar)) {
				destroy_piodma_device(dcp);
				return dev_err_probe(dev, PTR_ERR(dcp->xbar), "Failed to get dp-xbar\n");
			}
			ret = mux_control_select(dcp->xbar, mux_index);
			if (ret)
				dev_warn(dev, "mux_control_select failed: %d\n", ret);
			dcp->fixed_xbar = dcp->xbar;
			dcp->fixed_xbar_selected = !ret;
			/* after dcp_leave_switch(), which may select it again */
			ret = devm_add_action_or_reset(dev, dcp_deselect_fixed_xbar,
						       dcp);
			if (ret)
				return ret;

			/*
			 * Switch atcphy to DP-only. should move to a Macbook Pro
			 * 14-/16-inch specific DP-to-HDMI drm_bridge.
			 */
			dcp->typec_mux = fwnode_typec_mux_get(dev_fwnode(dcp->dev));
			if (!IS_ERR_OR_NULL(dcp->typec_mux)) {
				struct typec_altmode alt = {
					.svid = USB_TYPEC_DP_SID,
				};
				struct typec_mux_state state = {
					.alt = &alt,
					.mode = TYPEC_DP_STATE_C,
				};
				int ret = typec_mux_set(dcp->typec_mux, &state);
				dev_info(dev, "typec_mux_set() returned: %d\n", ret);
			} else {
				dev_info(dev, "fwnode_typec_mux_get() returned: %ld\n",
						IS_ERR(dcp->typec_mux) ? PTR_ERR(dcp->typec_mux) : 0);
				dcp->typec_mux = NULL;
			}
		}
	}

	/*
	 * Join the display switch last, once nothing above can fail or defer:
	 * the switch keeps a pointer to this devm allocation until the action
	 * removes it.
	 */
	if (dcp->dp_switch) {
		ret = dp_switch_add_dcp(dcp);
		if (ret)
			return dev_err_probe(dev, ret, "dp-switch is full\n");
		ret = devm_add_action_or_reset(dev, dcp_leave_switch, dcp);
		if (ret)
			return ret;
	}

	return component_add(&pdev->dev, &dcp_comp_ops);
}

static void dcp_platform_remove(struct platform_device *pdev)
{
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	component_del(&pdev->dev, &dcp_comp_ops);

	destroy_piodma_device(dcp);
}

static void dcp_platform_shutdown(struct platform_device *pdev)
{
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	component_del(&pdev->dev, &dcp_comp_ops);

	destroy_piodma_device(dcp);
}

/*
 * The DCP's restart after a power cut on the t6020 bench (native5, sleep/t6020-dcp-native, by
 * function): only at EL2 with apple_sleep.hybrid bits 26 and 9, on the internal DCP. The
 * configuration every native run with frames after a cut used (task 146: bench_idle 0x268f1388,
 * bench_afk_open 5), and only its live steps: at the end of the suspend, A500 and an RTKit idle
 * with the AFK queues stopped between the AP and IOP requests (sleep-seq's table then stops the
 * CPU); at the resume, the display block's power cycled as macOS does between its boots, the
 * RTKit session restarted warm with its OSLOG counters echoed, the CPU run and the AFK queues
 * started again. The bind-time AFK accept/open, the bench's register prints and the hybrid
 * bit 27 table stop are not carried; nothing here runs on a daily boot.
 */
#define DCP_BENCH_EL2_IDLE_MS	5000

static bool dcp_bench_el2(void)
{
	return is_kernel_in_hyp_mode() &&
	       (apple_sleep_bench_hybrid() & APPLE_SLEEP_HYBRID_DCP_EL2) &&
	       (apple_sleep_bench_hybrid() & APPLE_SLEEP_HYBRID_DCP_BOOT);
}

/* The internal DCP only: the HV arms never had the external ones bound */
static bool dcp_bench_el2_on(struct apple_dcp *dcp)
{
	return dcp_bench_el2() && !of_device_is_compatible(dcp->dev->of_node, "apple,dcpext") &&
	       dcp->coproc_reg && !IS_ERR_OR_NULL(dcp->rtk);
}

/* The AFK ring endpoints this driver started; macOS stops them between AP and IOP idle */
static unsigned int dcp_bench_afk_eps(struct apple_dcp *dcp, struct apple_dcp_afkep **eps,
				      unsigned int max)
{
	struct apple_dcp_afkep *all[] = { dcp->systemep, dcp->ibootep, dcp->dcpavservep,
					  dcp->avep, dcp->dptxep };
	unsigned int n = 0, i, j;

	for (i = 0; i < ARRAY_SIZE(all) && n < max; i++) {
		if (IS_ERR_OR_NULL(all[i]) || !completion_done(&all[i]->started))
			continue;
		for (j = 0; j < n && eps[j] != all[i]; j++)
			;
		if (j == n)
			eps[n++] = all[i];
	}
	return n;
}

/* 0xa4 stops a started queue and 0xa3 starts it again (aurora's aop_queue_stop) */
static void dcp_bench_afk_queue_op(struct apple_dcp *dcp, u16 op, const char *when)
{
	struct apple_dcp_afkep *eps[8];
	unsigned int n = dcp_bench_afk_eps(dcp, eps, ARRAY_SIZE(eps)), i;
	char list[64];
	size_t off = 0;

	list[0] = 0;
	for (i = 0; i < n; i++) {
		afk_bench_queue_op(eps[i], op);
		off += scnprintf(list + off, sizeof(list) - off, " %#x", eps[i]->endpoint);
	}
	dev_info(dcp->dev, "bench: afk queue %#x %s: %u endpoints:%s\n", op, when, n, list);
}

static void dcp_bench_afk_stop(void *data)
{
	dcp_bench_afk_queue_op(data, 0xa4, "after the AP idle request");
}

/*
 * macOS idles a DCP over RTKit with interrupts on, AP then IOP 0x201, before its CPU stop
 * (pdD1); the table's polled idle never got the AP ack (b1i, 9 of 9). So the idle runs here,
 * last in the suspend, after A500 drained the AP link; the table then only stops the CPU.
 */
static void dcp_bench_idle_at_suspend(struct apple_dcp *dcp)
{
	ktime_t t0;
	int ret;

	dcp->bench_idle_ran = false;
	if (!dcp_bench_el2_on(dcp) || !apple_rtkit_is_running(dcp->rtk))
		return;
	t0 = ktime_get();
	ret = iomfb_s2r_link_sleep(dcp);
	/* Its call never returned: the channel it took must not outlive the warm restart */
	dcp->bench_call_lost = ret == -ETIMEDOUT;
	dev_info(dcp->dev, "bench: dcp link sleep A500: %d after %lld ms\n", ret,
		 ktime_ms_delta(ktime_get(), t0));
	t0 = ktime_get();
	dcp->bench_idle_ret = apple_rtkit_bench_idle(dcp->rtk, DCP_BENCH_EL2_IDLE_MS,
						     dcp_bench_afk_stop, dcp);
	dcp->bench_idle_ran = true;
	dev_info(dcp->dev, "bench: dcp idle at suspend: %d after %lld ms\n", dcp->bench_idle_ret,
		 ktime_ms_delta(ktime_get(), t0));
}

static void __iomem *dcp_bench_ps_node_map(struct device_node *ps)
{
	struct device_node *pmgr = of_get_parent(ps);
	struct resource res;
	void __iomem *p = NULL;
	u32 off;

	if (pmgr && !of_property_read_u32_index(ps, "reg", 0, &off) &&
	    !of_address_to_resource(pmgr, 0, &res))
		p = (res.flags & IORESOURCE_MEM_NONPOSTED) ? ioremap_np(res.start + off, 4) :
							      ioremap(res.start + off, 4);
	of_node_put(pmgr);
	return p;
}

static int dcp_bench_ps_set(void __iomem *p, u32 val, u32 actual)
{
	u32 v;

	writel(val, p);
	return readl_poll_timeout(p, v, ((v >> 4) & 0xf) == actual, 10, 10000);
}

static struct device *dcp_bench_dart_dev(struct device_node *np, const char *prop)
{
	struct of_phandle_args args;
	struct platform_device *pdev;

	if (!np || of_parse_phandle_with_args(np, prop, "#iommu-cells", 0, &args))
		return NULL;
	pdev = of_find_device_by_node(args.np);
	of_node_put(args.np);
	return pdev ? &pdev->dev : NULL;
}

/*
 * Between its boots 1 and 2 at the wake, macOS powers the whole display block off and on
 * (pdD1/pdD6: cpu0 0xf0400ff, 0xf0403f0; fe and sys 0x3f0; then sys and fe 0 -> 0xf ->
 * 0x1000000f and cpu0 0xf040000 -> 0xf04000f -> 0x1f04000f). Our restart never turns sys or fe
 * off. The block's DARTs (dart-dcp0, and piodma's dart-disp0) lose their state with it: held
 * with their runtime reference across it, and put back before the restart's RUN.
 */
static void dcp_bench_disp0_cycle(struct apple_dcp *dcp)
{
	struct device_node *np = dcp->dev->of_node, *cpu0, *fe = NULL, *sys = NULL, *child;
	void __iomem *pc = NULL, *pf = NULL, *ps = NULL;
	struct device *darts[2];
	int held[2] = { -ENODEV, -ENODEV }, r[6] = { 0 }, i;

	cpu0 = of_parse_phandle(np, "resets", 0);
	if (cpu0)
		fe = of_parse_phandle(cpu0, "power-domains", 0);
	if (fe)
		sys = of_parse_phandle(fe, "power-domains", 0);
	if (cpu0 && fe && sys) {
		pc = dcp_bench_ps_node_map(cpu0);
		pf = dcp_bench_ps_node_map(fe);
		ps = dcp_bench_ps_node_map(sys);
	}
	of_node_put(sys);
	of_node_put(fe);
	of_node_put(cpu0);
	darts[0] = dcp_bench_dart_dev(np, "iommus");
	child = of_get_child_by_name(np, "piodma");
	darts[1] = dcp_bench_dart_dev(child, "iommus");
	of_node_put(child);
	if (!pc || !pf || !ps) {
		dev_info(dcp->dev, "bench: disp0 cycle: PS words not mapped, skipped\n");
		goto out;
	}

	/* rv-sepkey: both are locked on j416s (hold -95); whether the lock and tables survived the cut */
	for (i = 0; i < 2; i++) {
		char st[256];

		if (!darts[i])
			continue;
		apple_dart_bench_state(darts[i], st, sizeof(st));
		dev_info(dcp->dev, "bench: disp0 cycle: dart %s after the cut: %s\n", dev_name(darts[i]), st);
		held[i] = apple_dart_sleep_hold(darts[i]);
	}
	dev_info(dcp->dev, "bench: disp0 cycle: before cpu0 %#x fe %#x sys %#x, darts held %d %d\n",
		 readl(pc), readl(pf), readl(ps), held[0], held[1]);

	writel(0xf0400ff, pc);
	r[0] = dcp_bench_ps_set(pc, 0xf0403f0, 0);
	r[1] = dcp_bench_ps_set(pf, 0x3f0, 0);
	r[2] = dcp_bench_ps_set(ps, 0x3f0, 0);
	/* Off for a while, as macOS (~10 ms) and aurora's T6050 cycle (12 ms): a stopped core needs it */
	msleep(12);
	r[3] = dcp_bench_ps_set(ps, 0xf, 0xf);
	writel(0x1000000f, ps);
	r[4] = dcp_bench_ps_set(pf, 0xf, 0xf);
	writel(0x1000000f, pf);
	writel(0xf040000, pc);
	r[5] = dcp_bench_ps_set(pc, 0xf04000f, 0xf);
	writel(0x1f04000f, pc);

	for (i = 0; i < 2; i++)
		if (darts[i] && !held[i])
			apple_dart_sleep_restore_lost(darts[i], true);
	dev_info(dcp->dev, "bench: disp0 cycle: on cpu0 %#x fe %#x sys %#x (%d %d %d %d %d %d), darts restored\n",
		 readl(pc), readl(pf), readl(ps), r[0], r[1], r[2], r[3], r[4], r[5]);
out:
	for (i = 0; i < 2; i++)
		if (darts[i])
			put_device(darts[i]);
	if (pc)
		iounmap(pc);
	if (pf)
		iounmap(pf);
	if (ps)
		iounmap(ps);
}

/*
 * The sleep's table stopped the CPU (CPU_CONTROL 0) and nothing starts it again: without the
 * restart dcp_poweron() waits on a firmware that isn't running. Start it from the image it
 * kept: the display block cycled, RTKit restarted warm (its OSLOG counters echoed from here on,
 * or it refuses its next idle), the run bit, the boot, and the AFK queues started again.
 */
static void dcp_bench_boot(struct apple_dcp *dcp)
{
	void __iomem *control = dcp->coproc_reg + APPLE_DCP_COPROC_CPU_CONTROL;
	ktime_t t0 = ktime_get();
	int ret;

	if (!dcp_bench_el2_on(dcp) || (readl(control) & APPLE_DCP_COPROC_CPU_CONTROL_RUN))
		return;

	dcp_bench_disp0_cycle(dcp);
	WRITE_ONCE(dcp->crashed, false);
	apple_rtkit_set_oslog_echo(dcp->rtk, true);
	ret = apple_rtkit_warm_restart(dcp->rtk);
	if (ret) {
		dev_err(dcp->dev, "bench: dcp-boot: RTKit warm restart failed: %d\n", ret);
		return;
	}
	/* A call the old session never answered: its depth would wedge the new one's calls */
	if (dcp->bench_call_lost) {
		dcp->ch_cmd.depth = 0;
		dcp->ch_oobcmd.depth = 0;
		dcp->ch_cb.depth = 0;
		dcp->ch_oobcb.depth = 0;
		dcp->ch_async.depth = 0;
		dcp->ch_oobasync.depth = 0;
		dcp->bench_call_lost = false;
		dev_info(dcp->dev, "bench: dcp-boot: IOMFB channels reset after a lost call\n");
	}
	writel(APPLE_DCP_COPROC_CPU_CONTROL_RUN, control);
	ret = apple_rtkit_boot(dcp->rtk);
	dev_info(dcp->dev, "bench: dcp-boot: boot %d after %lld ms: CPU_CONTROL %#x, rtkit %s\n",
		 ret, ktime_ms_delta(ktime_get(), t0), readl(control),
		 apple_rtkit_is_running(dcp->rtk) ? "running" : "not running");
	/* As macOS after every AP ON: the queues stopped at suspend start again */
	if (!ret)
		dcp_bench_afk_queue_op(dcp, 0xa3, "after the boot");
}

/*
 * An idle external DCP across S2R (rv-dpswitch fa6f9d6 item 3): with no route (dp-switch's
 * sleep_hold released it, or none was set up) and no CRTC on, there is no display state to
 * keep. Only for a real sleep (suspend via firmware) or with appledrm.dcpext_sleep_stop: its
 * link drained (A500 on 13.5), its firmware idled and its CPU stopped with the session kept,
 * and no wakeup path, so genpd takes ps_dispextN_cpu0 -> fe -> sys down and sleep-seq leaves
 * its request out of the PMP report. At the resume the display block is cycled as for the
 * internal DCP (batch 11) and the session restarted warm; after a refused sleep the cycle is
 * the reset native5 gives SIO, and the same restart follows. A failed restart falls back to
 * RTKit's cold start. Anything else keeps today's path: wakeup path, nothing stopped.
 */
static bool dcpext_sleep_stop;
module_param(dcpext_sleep_stop, bool, 0444);
MODULE_PARM_DESC(dcpext_sleep_stop, "bench: stop an idle external DCP for S2R without suspend_via_firmware");

/*
 * Idle: dp-switch holds its passes for the sleep (sleep_hold, so no pass can route it while
 * this runs, and every route was released at the prepare), no route is set, and its CRTC is
 * off (apple-drm's suspend ran first). rv-dpswitch a9161b3: dcp->active is "booted", not this.
 */
static bool dcp_dcpext_stop_wanted(struct apple_dcp *dcp)
{
	struct drm_crtc_state *cs = dcp->crtc ? dcp->crtc->base.state : NULL;

	return of_device_is_compatible(dcp->dev->of_node, "apple,dcpext") &&
	       (pm_suspend_via_firmware() || dcpext_sleep_stop) && dcp->coproc_reg &&
	       !IS_ERR_OR_NULL(dcp->rtk) && apple_rtkit_is_running(dcp->rtk) &&
	       !READ_ONCE(dcp->crashed) && apple_dp_switch_held() && !dcp->switch_active &&
	       !(cs && cs->active) &&
	       /* dcpext0's fixed HDMI route (atc3 DP-only, the pwren GPIOs) isn't released for it */
	       !dcp_hdmi_connected(dcp);
}

/*
 * sleep-seq's check at .begin (design review must-fix 3): why this external DCP won't stop for
 * the coming S2R, or NULL. Its sleep would otherwise keep its domains on and end in a no-cut.
 * dp-switch's hold is already set: PM_SUSPEND_PREPARE runs before the platform's .begin.
 */
static const char *dcp_dcpext_sleep_veto(struct device *dev, bool via_firmware)
{
	struct apple_dcp *dcp = dev_get_drvdata(dev);

	if (!dcp || !dcp->coproc_reg || IS_ERR_OR_NULL(dcp->rtk) || !apple_rtkit_is_running(dcp->rtk))
		return "its firmware isn't running";
	if (READ_ONCE(dcp->crashed))
		return "its firmware crashed";
	if (!via_firmware && !dcpext_sleep_stop)
		return "not a suspend via firmware (apple_sleep.via_firmware), so it keeps its domains";
	if (!apple_dp_switch_held())
		return "appledrm.sleep_hold is off, so it keeps its domains";
	/* dcpext0's fixed HDMI route (atc3, the pwren GPIOs) isn't released for a sleep */
	if (dcp->hdmi_hpd && gpiod_get_value_cansleep(dcp->hdmi_hpd))
		return "an HDMI sink is attached";
	return NULL;
}

static void dcp_dcpext_sleep_register(struct apple_dcp *dcp, bool on)
{
	if (of_device_is_compatible(dcp->dev->of_node, "apple,dcpext"))
		apple_sleep_dispext_register(dcp->dev, on ? dcp_dcpext_sleep_veto : NULL);
}

/* As batch 11's internal idle: AP idle, AFK queues stopped (0xa4), IOP idle, 5 s per ack */
static int dcp_dcpext_idle_stop(struct apple_dcp *dcp)
{
	void __iomem *control = dcp->coproc_reg + APPLE_DCP_COPROC_CPU_CONTROL;
	u32 status;
	int ret;

	ret = apple_rtkit_bench_idle(dcp->rtk, DCP_BENCH_EL2_IDLE_MS, dcp_bench_afk_stop, dcp);
	if (ret)
		return ret;
	if (readl_poll_timeout(dcp->coproc_reg + APPLE_DCP_COPROC_CPU_STATUS, status,
			       (status & APPLE_DCP_COPROC_CPU_STATUS_DOWN) ==
			       APPLE_DCP_COPROC_CPU_STATUS_DOWN, 100, 5000))
		dev_warn(dcp->dev, "dcpext sleep: idle, but not stopped: status %#x\n", status);
	apple_rtkit_mailbox_off(dcp->rtk);
	/* As macOS stops it: twice */
	writel(readl(control) & ~APPLE_DCP_COPROC_CPU_CONTROL_RUN, control);
	writel(readl(control) & ~APPLE_DCP_COPROC_CPU_CONTROL_RUN, control);
	return 0;
}

/*
 * dcpext0's HDMI converter power (hdmi-pwren, dp2hdmi-pwren), high since probe for the HPD
 * irq: low through the sleep of a stopped dcpext with no sink, high again (probe's order)
 * before its restart. Kept high, it costs 0.126 W in the cut (nopwr-a/b, 2 of 2).
 */
static void dcp_hdmi_power(struct apple_dcp *dcp, bool on)
{
	if (!dcp->hdmi_pwren && !dcp->dp2hdmi_pwren)
		return;
	if (on) {
		if (!dcp->hdmi_power_cut)
			return;
		gpiod_set_value_cansleep(dcp->hdmi_pwren, 1);
		gpiod_set_value_cansleep(dcp->dp2hdmi_pwren, 1);
		dcp->hdmi_power_cut = false;
	} else {
		gpiod_set_value_cansleep(dcp->dp2hdmi_pwren, 0);
		gpiod_set_value_cansleep(dcp->hdmi_pwren, 0);
		dcp->hdmi_power_cut = true;
	}
	dev_info(dcp->dev, "dcpext sleep: HDMI converter power %s\n", on ? "on again" : "off");
}

/* True if it stopped: then no wakeup path */
static bool dcp_dcpext_sleep_stop(struct apple_dcp *dcp)
{
	void __iomem *control = dcp->coproc_reg + APPLE_DCP_COPROC_CPU_CONTROL;
	int ret;

	dcp->dcpext_half = false;
	if (!dcp_dcpext_stop_wanted(dcp))
		return false;
	ret = iomfb_s2r_link_sleep(dcp);
	dcp->bench_call_lost = ret == -ETIMEDOUT;
	ret = dcp_dcpext_idle_stop(dcp);
	if (ret) {
		/* Not idle: it keeps running, with its domains, as today, if it still answers */
		dev_warn(dcp->dev, "dcpext sleep: firmware did not stop (%d)\n", ret);
		if (!apple_rtkit_sleep_return(dcp->rtk, control)) {
			/* Its link asleep (A500) and its AFK queues stopped: the fallback undoes them */
			dcp->dcpext_half = true;
			return false;
		}
		/*
		 * Half idle (AP took, IOP didn't): it won't run on as it is (rv-dpswitch item 3).
		 * Stopped like an idled one, so the resume restarts it from the cycle.
		 */
		dev_warn(dcp->dev, "dcpext sleep: half idle, stopped as an idled one\n");
		apple_rtkit_mailbox_off(dcp->rtk);
		writel(readl(control) & ~APPLE_DCP_COPROC_CPU_CONTROL_RUN, control);
		writel(readl(control) & ~APPLE_DCP_COPROC_CPU_CONTROL_RUN, control);
	}
	dcp->dcpext_stopped = true;
	apple_sleep_dispext_down(dcp->dev, true);
	/* stop_wanted saw no HDMI sink: nothing needs the converter until the wake */
	dcp_hdmi_power(dcp, false);
	dev_info(dcp->dev, "dcpext sleep: idle, firmware stopped, domains released\n");
	return true;
}

static void dcp_dcpext_sleep_return(struct apple_dcp *dcp)
{
	void __iomem *control = dcp->coproc_reg + APPLE_DCP_COPROC_CPU_CONTROL;
	bool real = pm_resume_via_firmware();
	int ret;

	if (!dcp->dcpext_stopped)
		return;
	dcp->dcpext_stopped = false;
	/* Before the restart, after a cut and after a refused sleep alike */
	dcp_hdmi_power(dcp, true);

	/* The power cycle macOS gives the block between its boots, and the reset of a refused sleep */
	dcp_bench_disp0_cycle(dcp);
	/* After the cycle: its PMP request again */
	apple_sleep_dispext_down(dcp->dev, false);
	if (dcp->bench_call_lost) {
		dcp->ch_cmd.depth = 0;
		dcp->ch_oobcmd.depth = 0;
		dcp->ch_cb.depth = 0;
		dcp->ch_oobcb.depth = 0;
		dcp->ch_async.depth = 0;
		dcp->ch_oobasync.depth = 0;
		dcp->bench_call_lost = false;
	}
	WRITE_ONCE(dcp->crashed, false);
	apple_rtkit_set_oslog_echo(dcp->rtk, true);
	ret = real ? apple_rtkit_sleep_return(dcp->rtk, control) :
		     apple_rtkit_power_cycled_return(dcp->rtk, control);
	if (!ret) {
		struct apple_dcp_afkep *eps[8];
		unsigned int n = dcp_bench_afk_eps(dcp, eps, ARRAY_SIZE(eps)), i;

		for (i = 0; i < n; i++)
			afk_bench_queue_op(eps[i], 0xa3);
		dev_info(dcp->dev, "dcpext sleep: back after %s, %u AFK queues started\n",
			 real ? "the sleep" : "a refused sleep", n);
		return;
	}
	/* RTKit's own cold start, as at the bind: the firmware comes up, even if not all of it */
	dev_err(dcp->dev, "dcpext sleep: warm restart failed (%d), starting it cold\n", ret);
	ret = apple_rtkit_reinit(dcp->rtk);
	if (!ret) {
		writel_relaxed(readl_relaxed(control) | APPLE_DCP_COPROC_CPU_CONTROL_RUN, control);
		ret = apple_rtkit_wake(dcp->rtk);
	}
	if (ret)
		dev_err(dcp->dev, "dcpext sleep: cold start failed: %d\n", ret);
	/*
	 * Cold, its endpoints aren't started again (no dcp_start): unusable for the switch,
	 * which would route a sink to it (rv-dpswitch item 5), until a rebind.
	 */
	WRITE_ONCE(dcp->crashed, true);
	dev_crit(dcp->dev, "dcpext sleep: not usable for displays until it is bound again\n");
}

static int dcp_platform_suspend(struct device *dev)
{
	struct apple_dcp *dcp = dev_get_drvdata(dev);

	if (dcp->avep)
		av_service_disconnect(dcp);

	if (dcp->hdmi_hpd_irq) {
		disable_irq(dcp->hdmi_hpd_irq);
		disconnected_hpd_event(dcp->connector);
		dcp_dptx_disconnect(dcp, 0);
	}
	/* An idle external DCP stopped for a real sleep: its domains may go */
	if (dcp_dcpext_sleep_stop(dcp))
		return 0;
	/*
	 * Late fallback (.begin's check passed): a stop that was expected didn't happen (a route or
	 * a CRTC still on, or its firmware didn't idle). Its domains would hold the sleep in a
	 * no-cut: refuse it, after undoing the steps above.
	 */
	if (of_device_is_compatible(dcp->dev->of_node, "apple,dcpext") &&
	    pm_suspend_via_firmware() && apple_dp_switch_held()) {
		bool half = dcp->dcpext_half;

		dcp->dcpext_half = false;
		if (half) {
			struct apple_dcp_afkep *eps[8];
			unsigned int n = dcp_bench_afk_eps(dcp, eps, ARRAY_SIZE(eps)), i;

			/*
			 * Its stop got as far as the A500 link sleep and the AFK queue stop before the
			 * idle failed: the queues start again, but nothing wakes the link (no call
			 * for it): unusable for displays until a rebind, as after a cold start.
			 */
			for (i = 0; i < n; i++)
				afk_bench_queue_op(eps[i], 0xa3);
			WRITE_ONCE(dcp->crashed, true);
			dev_crit(dev, "dcpext sleep: half stopped (its link asleep): not usable for displays until it is bound again\n");
		}
		if (apple_sleep_dispext_refuses()) {
			dev_err(dev, "dcpext sleep: not stopped, the sleep is refused\n");
			if (dcp->hdmi_hpd_irq)
				enable_irq(dcp->hdmi_hpd_irq);
			if (dcp->avep)
				av_service_connect(dcp);
			return -EBUSY;
		}
		dev_warn(dev, "dcpext sleep: not stopped, kept on (apple_sleep.dispext_refuse=0)\n");
	}
	/*
	 * Set the device as a wakeup device, which forces its power
	 * domains to stay on. We need this as we do not support full
	 * shutdown properly yet.
	 */
	device_set_wakeup_path(dev);
	/* Last: the steps above still talk to the coprocessor (bench only) */
	dcp_bench_idle_at_suspend(dcp);

	return 0;
}

static int dcp_platform_resume(struct device *dev)
{
	struct apple_dcp *dcp = dev_get_drvdata(dev);

	/* First: nothing below may talk to a firmware the sleep's table stopped (bench only) */
	dcp_bench_boot(dcp);
	/* Or that its own suspend stopped (an idle external DCP) */
	dcp_dcpext_sleep_return(dcp);

	if (dcp->hdmi_hpd_irq)
		enable_irq(dcp->hdmi_hpd_irq);

	if (dcp->avep)
		av_service_connect(dcp);

	return 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(dcp_platform_pm_ops,
				dcp_platform_suspend, dcp_platform_resume);


static const struct apple_dcp_hw_data apple_dcp_hw_t6020 = {
	.num_dptx_ports = 1,
};

static const struct apple_dcp_hw_data apple_dcp_hw_t8112 = {
	.num_dptx_ports = 2,
};

static const struct apple_dcp_hw_data apple_dcp_hw_dcp = {
	.num_dptx_ports = 0,
};

static const struct apple_dcp_hw_data apple_dcp_hw_dcpext = {
	.num_dptx_ports = 2,
};

static const struct of_device_id of_match[] = {
	{ .compatible = "apple,t6020-dcp", .data = &apple_dcp_hw_t6020,  },
	{ .compatible = "apple,t8112-dcp", .data = &apple_dcp_hw_t8112,  },
	{ .compatible = "apple,dcp",       .data = &apple_dcp_hw_dcp,    },
	{ .compatible = "apple,dcpext",    .data = &apple_dcp_hw_dcpext, },
	{}
};
MODULE_DEVICE_TABLE(of, of_match);

static struct platform_driver apple_platform_driver = {
	.probe		= dcp_platform_probe,
	.remove		= dcp_platform_remove,
	.shutdown	= dcp_platform_shutdown,
	.driver	= {
		.name = "apple-dcp",
		.of_match_table	= of_match,
		.pm = pm_sleep_ptr(&dcp_platform_pm_ops),
	},
};

void __init dcp_register(void)
{
	platform_driver_register(&apple_platform_driver);
}

void __exit dcp_unregister(void)
{
	platform_driver_unregister(&apple_platform_driver);
}
