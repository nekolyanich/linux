/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * Apple RTKit IPC library
 * Copyright (C) The Asahi Linux Contributors
 */

#ifndef _APPLE_RTKIT_INTERAL_H
#define _APPLE_RTKIT_INTERAL_H

#include <linux/bitfield.h>
#include <linux/bitmap.h>
#include <linux/completion.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/soc/apple/mailbox.h>
#include <linux/soc/apple/rtkit.h>
#include <linux/workqueue.h>

#define APPLE_RTKIT_APP_ENDPOINT_START 0x20
#define APPLE_RTKIT_MAX_ENDPOINTS 0x100

struct apple_rtkit {
	void *cookie;
	const struct apple_rtkit_ops *ops;
	struct device *dev;

	struct apple_mbox *mbox;

	/* Each handshake step's wait, apple_rtkit_set_handshake_timeout() */
	unsigned int handshake_timeout_ms;
	/* apple_rtkit_ap_power_noirq: the handshake waits poll the mailbox in 10 ms slices (aurora) */
	bool poll_waits;
	/*
	 * apple_rtkit_warm_restart (aurora, retained session): the next endpoint
	 * map is answered as macOS answers a restarted coprocessor, echoing the
	 * map, and starts no endpoint; warm_last_mask limits the last part's echo.
	 */
	bool warm_restart;
	u32 warm_last_mask;
	/* Restarted warm since the last reinit: the buffers stay live */
	bool warm_session;
	/* apple_rtkit_set_oslog_echo: OSLOG counters echoed; one the receive work still owes */
	bool oslog_echo;
	u64 oslog_owed;

	struct completion epmap_completion;
	struct completion iop_pwr_ack_completion;
	struct completion ap_pwr_ack_completion;

	int boot_result;
	int version;

	unsigned int iop_power_state;
	unsigned int ap_power_state;
	bool crashed;

	DECLARE_BITMAP(endpoints, APPLE_RTKIT_MAX_ENDPOINTS);

	struct apple_rtkit_shmem ioreport_buffer;
	struct apple_rtkit_shmem crashlog_buffer;
	struct apple_rtkit_shmem oslog_buffer;

	struct apple_rtkit_shmem syslog_buffer;
	char *syslog_msg_buffer;
	size_t syslog_n_entries;
	size_t syslog_msg_size;

	struct workqueue_struct *wq;
};

void apple_rtkit_crashlog_dump(struct apple_rtkit *rtk, u8 *bfr, size_t size);

#endif
