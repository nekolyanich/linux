/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * Apple Silicon Display Crossbar: consumer API beyond the mux framework
 */

#ifndef _LINUX_MUX_APPLE_DISPLAY_CROSSBAR_H
#define _LINUX_MUX_APPLE_DISPLAY_CROSSBAR_H

struct mux_control;

#if IS_REACHABLE(CONFIG_MUX_APPLE_DPXBAR)
/*
 * Finish routing a selected t602x dpin output (FIFO and clock enables) once
 * the consumer's link is set up. Returns -EALREADY if nothing was pending.
 */
int apple_dpxbar_finish(struct mux_control *mux);
int apple_dpxbar_link_down(struct mux_control *mux);
#else
static inline int apple_dpxbar_finish(struct mux_control *mux)
{
	return -EALREADY;
}

static inline int apple_dpxbar_link_down(struct mux_control *mux)
{
	return -EALREADY;
}
#endif

#endif /* _LINUX_MUX_APPLE_DISPLAY_CROSSBAR_H */
