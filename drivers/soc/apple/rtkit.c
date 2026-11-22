// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Apple RTKit IPC library
 * Copyright (C) The Asahi Linux Contributors
 */

#include <linux/delay.h>
#include <linux/suspend.h>
#include <linux/iopoll.h>
#include "rtkit-internal.h"

/* Default wait for each handshake reply, see apple_rtkit_set_handshake_timeout() (aurora) */
#define APPLE_RTKIT_HANDSHAKE_TIMEOUT_MS 1000

/* The ASC CPU's registers, as the callers pass them (aurora) */
#define APPLE_ASC_CPU_CONTROL_RUN	BIT(4)
#define APPLE_ASC_CPU_STATUS		4
#define APPLE_ASC_CPU_STATUS_STOPPED	BIT(1)
#define APPLE_ASC_CPU_STATUS_IDLE	BIT(5)
#define APPLE_ASC_CPU_STATUS_DOWN	(APPLE_ASC_CPU_STATUS_STOPPED | APPLE_ASC_CPU_STATUS_IDLE)

enum {
	APPLE_RTKIT_PWR_STATE_OFF = 0x00, /* power off, cannot be restarted */
	APPLE_RTKIT_PWR_STATE_SLEEP = 0x01, /* sleeping, can be restarted */
	APPLE_RTKIT_PWR_STATE_IDLE = 0x201, /* sleeping, retain state */
	APPLE_RTKIT_PWR_STATE_QUIESCED = 0x10, /* running but no communication */
	APPLE_RTKIT_PWR_STATE_ON = 0x20, /* normal operating state */
	APPLE_RTKIT_PWR_STATE_INIT = 0x220, /* init after starting the coproc */
};

enum {
	APPLE_RTKIT_EP_MGMT = 0,
	APPLE_RTKIT_EP_CRASHLOG = 1,
	APPLE_RTKIT_EP_SYSLOG = 2,
	APPLE_RTKIT_EP_DEBUG = 3,
	APPLE_RTKIT_EP_IOREPORT = 4,
	APPLE_RTKIT_EP_OSLOG = 8,
};

#define APPLE_RTKIT_MGMT_TYPE GENMASK_ULL(59, 52)

enum {
	APPLE_RTKIT_MGMT_HELLO = 1,
	APPLE_RTKIT_MGMT_HELLO_REPLY = 2,
	APPLE_RTKIT_MGMT_STARTEP = 5,
	APPLE_RTKIT_MGMT_SET_IOP_PWR_STATE = 6,
	APPLE_RTKIT_MGMT_SET_IOP_PWR_STATE_ACK = 7,
	APPLE_RTKIT_MGMT_EPMAP = 8,
	APPLE_RTKIT_MGMT_EPMAP_REPLY = 8,
	APPLE_RTKIT_MGMT_SET_AP_PWR_STATE = 0xb,
	APPLE_RTKIT_MGMT_SET_AP_PWR_STATE_ACK = 0xb,
};

#define APPLE_RTKIT_MGMT_HELLO_MINVER GENMASK_ULL(15, 0)
#define APPLE_RTKIT_MGMT_HELLO_MAXVER GENMASK_ULL(31, 16)

#define APPLE_RTKIT_MGMT_EPMAP_LAST   BIT_ULL(51)
#define APPLE_RTKIT_MGMT_EPMAP_BASE   GENMASK_ULL(34, 32)
#define APPLE_RTKIT_MGMT_EPMAP_BITMAP GENMASK_ULL(31, 0)

#define APPLE_RTKIT_MGMT_EPMAP_REPLY_MORE BIT_ULL(0)

#define APPLE_RTKIT_MGMT_STARTEP_EP   GENMASK_ULL(39, 32)
#define APPLE_RTKIT_MGMT_STARTEP_FLAG BIT_ULL(1)

#define APPLE_RTKIT_MGMT_PWR_STATE GENMASK_ULL(15, 0)

#define APPLE_RTKIT_CRASHLOG_CRASH 1

#define APPLE_RTKIT_BUFFER_REQUEST	1
#define APPLE_RTKIT_BUFFER_REQUEST_SIZE GENMASK_ULL(51, 44)
#define APPLE_RTKIT_BUFFER_REQUEST_IOVA GENMASK_ULL(43, 0)

#define APPLE_RTKIT_SYSLOG_TYPE GENMASK_ULL(59, 52)

#define APPLE_RTKIT_SYSLOG_LOG 5

#define APPLE_RTKIT_SYSLOG_INIT	     8
#define APPLE_RTKIT_SYSLOG_N_ENTRIES GENMASK_ULL(7, 0)
#define APPLE_RTKIT_SYSLOG_MSG_SIZE  GENMASK_ULL(31, 24)

#define APPLE_RTKIT_OSLOG_TYPE GENMASK_ULL(63, 56)
#define APPLE_RTKIT_OSLOG_BUFFER_REQUEST 1
#define APPLE_RTKIT_OSLOG_SIZE GENMASK_ULL(55, 36)
#define APPLE_RTKIT_OSLOG_IOVA GENMASK_ULL(35, 0)

#define APPLE_RTKIT_MIN_SUPPORTED_VERSION 11
#define APPLE_RTKIT_MAX_SUPPORTED_VERSION 12

struct apple_rtkit_rx_work {
	struct apple_rtkit *rtk;
	u8 ep;
	u64 msg;
	struct work_struct work;
};

bool apple_rtkit_is_running(struct apple_rtkit *rtk)
{
	if (rtk->crashed)
		return false;
	if ((rtk->iop_power_state & 0xff) != APPLE_RTKIT_PWR_STATE_ON)
		return false;
	if ((rtk->ap_power_state & 0xff) != APPLE_RTKIT_PWR_STATE_ON)
		return false;
	return true;
}
EXPORT_SYMBOL_GPL(apple_rtkit_is_running);

bool apple_rtkit_is_crashed(struct apple_rtkit *rtk)
{
	return rtk->crashed;
}
EXPORT_SYMBOL_GPL(apple_rtkit_is_crashed);

static int apple_rtkit_management_send(struct apple_rtkit *rtk, u8 type,
					u64 msg)
{
	int ret;

	msg &= ~APPLE_RTKIT_MGMT_TYPE;
	msg |= FIELD_PREP(APPLE_RTKIT_MGMT_TYPE, type);
	ret = apple_rtkit_send_message(rtk, APPLE_RTKIT_EP_MGMT, msg, NULL, false);

	if (ret)
		dev_err(rtk->dev, "RTKit: Failed to send management message: %d\n", ret);

	return ret;
}

static void apple_rtkit_management_rx_hello(struct apple_rtkit *rtk, u64 msg)
{
	u64 reply;

	int min_ver = FIELD_GET(APPLE_RTKIT_MGMT_HELLO_MINVER, msg);
	int max_ver = FIELD_GET(APPLE_RTKIT_MGMT_HELLO_MAXVER, msg);
	int want_ver = min(APPLE_RTKIT_MAX_SUPPORTED_VERSION, max_ver);

	dev_dbg(rtk->dev, "RTKit: Min ver %d, max ver %d\n", min_ver, max_ver);

	if (min_ver > APPLE_RTKIT_MAX_SUPPORTED_VERSION) {
		dev_err(rtk->dev, "RTKit: Firmware min version %d is too new\n",
			min_ver);
		goto abort_boot;
	}

	if (max_ver < APPLE_RTKIT_MIN_SUPPORTED_VERSION) {
		dev_err(rtk->dev, "RTKit: Firmware max version %d is too old\n",
			max_ver);
		goto abort_boot;
	}

	dev_info(rtk->dev, "RTKit: Initializing (protocol version %d)\n",
		 want_ver);
	rtk->version = want_ver;

	reply = FIELD_PREP(APPLE_RTKIT_MGMT_HELLO_MINVER, want_ver);
	reply |= FIELD_PREP(APPLE_RTKIT_MGMT_HELLO_MAXVER, want_ver);
	apple_rtkit_management_send(rtk, APPLE_RTKIT_MGMT_HELLO_REPLY, reply);

	return;

abort_boot:
	rtk->boot_result = -EINVAL;
	complete_all(&rtk->epmap_completion);
}

static void apple_rtkit_management_rx_epmap(struct apple_rtkit *rtk, u64 msg)
{
	int i, ep;
	u64 reply;
	unsigned long bitmap = FIELD_GET(APPLE_RTKIT_MGMT_EPMAP_BITMAP, msg);
	u32 base = FIELD_GET(APPLE_RTKIT_MGMT_EPMAP_BASE, msg);

	dev_dbg(rtk->dev,
		"RTKit: received endpoint bitmap 0x%lx with base 0x%x\n",
		bitmap, base);

	for_each_set_bit(i, &bitmap, 32) {
		ep = 32 * base + i;
		dev_dbg(rtk->dev, "RTKit: Discovered endpoint 0x%02x\n", ep);
		set_bit(ep, rtk->endpoints);
	}

	reply = FIELD_PREP(APPLE_RTKIT_MGMT_EPMAP_BASE, base);
	if (msg & APPLE_RTKIT_MGMT_EPMAP_LAST)
		reply |= APPLE_RTKIT_MGMT_EPMAP_LAST;
	else
		reply |= APPLE_RTKIT_MGMT_EPMAP_REPLY_MORE;

	/*
	 * macOS's reply to a restarted coprocessor echoes the map, and adds bit 1
	 * to the first part: 0x51d becomes 0x51f. It starts no endpoints.
	 * Measured under aura on a DCP, 3 of 3 (aurora).
	 */
	if (rtk->warm_restart) {
		if (msg & APPLE_RTKIT_MGMT_EPMAP_LAST)
			reply |= bitmap & rtk->warm_last_mask;
		else
			reply |= bitmap | BIT_ULL(1);
	}

	apple_rtkit_management_send(rtk, APPLE_RTKIT_MGMT_EPMAP_REPLY, reply);

	if (!(msg & APPLE_RTKIT_MGMT_EPMAP_LAST))
		return;

	if (rtk->warm_restart) {
		rtk->warm_restart = false;
		rtk->boot_result = 0;
		complete_all(&rtk->epmap_completion);
		return;
	}

	for_each_set_bit(ep, rtk->endpoints, APPLE_RTKIT_APP_ENDPOINT_START) {
		switch (ep) {
		/* the management endpoint is started by default */
		case APPLE_RTKIT_EP_MGMT:
			break;

		/* without starting these RTKit refuses to boot */
		case APPLE_RTKIT_EP_SYSLOG:
		case APPLE_RTKIT_EP_CRASHLOG:
		case APPLE_RTKIT_EP_DEBUG:
		case APPLE_RTKIT_EP_IOREPORT:
		case APPLE_RTKIT_EP_OSLOG:
			dev_dbg(rtk->dev,
				"RTKit: Starting system endpoint 0x%02x\n", ep);
			apple_rtkit_start_ep(rtk, ep);
			break;

		default:
			dev_warn(rtk->dev,
				 "RTKit: Unknown system endpoint: 0x%02x\n",
				 ep);
		}
	}

	rtk->boot_result = 0;
	complete_all(&rtk->epmap_completion);
}

static void apple_rtkit_management_rx_iop_pwr_ack(struct apple_rtkit *rtk,
						  u64 msg)
{
	unsigned int new_state = FIELD_GET(APPLE_RTKIT_MGMT_PWR_STATE, msg);

	dev_dbg(rtk->dev, "RTKit: IOP power state transition: 0x%x -> 0x%x\n",
		rtk->iop_power_state, new_state);
	rtk->iop_power_state = new_state;

	complete_all(&rtk->iop_pwr_ack_completion);
}

static void apple_rtkit_management_rx_ap_pwr_ack(struct apple_rtkit *rtk,
						 u64 msg)
{
	unsigned int new_state = FIELD_GET(APPLE_RTKIT_MGMT_PWR_STATE, msg);

	dev_dbg(rtk->dev, "RTKit: AP power state transition: 0x%x -> 0x%x\n",
		rtk->ap_power_state, new_state);
	rtk->ap_power_state = new_state;

	complete_all(&rtk->ap_pwr_ack_completion);
}

static void apple_rtkit_management_rx(struct apple_rtkit *rtk, u64 msg)
{
	u8 type = FIELD_GET(APPLE_RTKIT_MGMT_TYPE, msg);

	switch (type) {
	case APPLE_RTKIT_MGMT_HELLO:
		apple_rtkit_management_rx_hello(rtk, msg);
		break;
	case APPLE_RTKIT_MGMT_EPMAP:
		apple_rtkit_management_rx_epmap(rtk, msg);
		break;
	case APPLE_RTKIT_MGMT_SET_IOP_PWR_STATE_ACK:
		apple_rtkit_management_rx_iop_pwr_ack(rtk, msg);
		break;
	case APPLE_RTKIT_MGMT_SET_AP_PWR_STATE_ACK:
		apple_rtkit_management_rx_ap_pwr_ack(rtk, msg);
		break;
	default:
		dev_warn(
			rtk->dev,
			"RTKit: unknown management message: 0x%llx (type: 0x%02x)\n",
			msg, type);
	}
}

static int apple_rtkit_common_rx_get_buffer(struct apple_rtkit *rtk,
					    struct apple_rtkit_shmem *buffer,
					    u8 ep, u64 msg)
{
	u64 reply;
	int err;

	/*
	 * After a warm restart the session's buffers are live (aurora): an
	 * identical request gets the same reply again, a changed one is refused.
	 */
	if (rtk->warm_session && buffer->size) {
		size_t size;
		dma_addr_t iova;

		if (ep == APPLE_RTKIT_EP_OSLOG) {
			size = FIELD_GET(APPLE_RTKIT_OSLOG_SIZE, msg);
			iova = FIELD_GET(APPLE_RTKIT_OSLOG_IOVA, msg) << 12;
		} else {
			size = FIELD_GET(APPLE_RTKIT_BUFFER_REQUEST_SIZE, msg) << 12;
			iova = FIELD_GET(APPLE_RTKIT_BUFFER_REQUEST_IOVA, msg);
		}
		if (size != buffer->size || (iova != buffer->iova && (iova || buffer->is_mapped))) {
			dev_err(rtk->dev,
				"RTKit: buffer request for 0x%zx bytes at %pad while 0x%zx bytes at %pad are live\n",
				size, &iova, buffer->size, &buffer->iova);
			return -EBUSY;
		}
		if (buffer->is_mapped)
			return 0;
		goto reply;
	}

	/* The different size vs. IOVA shifts look odd but are indeed correct this way */
	if (ep == APPLE_RTKIT_EP_OSLOG) {
		buffer->size = FIELD_GET(APPLE_RTKIT_OSLOG_SIZE, msg);
		buffer->iova = FIELD_GET(APPLE_RTKIT_OSLOG_IOVA, msg) << 12;
	} else {
		buffer->size = FIELD_GET(APPLE_RTKIT_BUFFER_REQUEST_SIZE, msg) << 12;
		buffer->iova = FIELD_GET(APPLE_RTKIT_BUFFER_REQUEST_IOVA, msg);
	}

	buffer->buffer = NULL;
	buffer->iomem = NULL;
	buffer->is_mapped = false;

	dev_dbg(rtk->dev, "RTKit: buffer request for 0x%zx bytes at %pad\n",
		buffer->size, &buffer->iova);

	if (buffer->iova && !rtk->ops->shmem_setup) {
		err = -EINVAL;
		goto error;
	}

	if (rtk->ops->shmem_setup) {
		err = rtk->ops->shmem_setup(rtk->cookie, buffer);
		if (err)
			goto error;
	} else {
		buffer->buffer = dma_alloc_coherent(rtk->dev, buffer->size,
						    &buffer->iova, GFP_KERNEL);
		if (!buffer->buffer) {
			err = -ENOMEM;
			goto error;
		}
	}

reply:
	if (!buffer->is_mapped) {
		/* oslog uses different fields and needs a shifted IOVA instead of size */
		if (ep == APPLE_RTKIT_EP_OSLOG) {
			reply = FIELD_PREP(APPLE_RTKIT_OSLOG_TYPE,
					   APPLE_RTKIT_OSLOG_BUFFER_REQUEST);
			reply |= FIELD_PREP(APPLE_RTKIT_OSLOG_SIZE, buffer->size);
			reply |= FIELD_PREP(APPLE_RTKIT_OSLOG_IOVA,
					    buffer->iova >> 12);
		} else {
			reply = FIELD_PREP(APPLE_RTKIT_SYSLOG_TYPE,
					   APPLE_RTKIT_BUFFER_REQUEST);
			reply |= FIELD_PREP(APPLE_RTKIT_BUFFER_REQUEST_SIZE,
					    buffer->size >> 12);
			reply |= FIELD_PREP(APPLE_RTKIT_BUFFER_REQUEST_IOVA,
					    buffer->iova);
		}
		apple_rtkit_send_message(rtk, ep, reply, NULL, false);
	}

	return 0;

error:
	dev_err(rtk->dev, "RTKit: failed buffer request for 0x%zx bytes (%d)\n",
		buffer->size, err);

	buffer->buffer = NULL;
	buffer->iomem = NULL;
	buffer->iova = 0;
	buffer->size = 0;
	buffer->is_mapped = false;
	return err;
}

static void apple_rtkit_free_buffer(struct apple_rtkit *rtk,
				    struct apple_rtkit_shmem *bfr)
{
	if (bfr->size == 0)
		return;

	if (rtk->ops->shmem_destroy)
		rtk->ops->shmem_destroy(rtk->cookie, bfr);
	else if (bfr->buffer)
		dma_free_coherent(rtk->dev, bfr->size, bfr->buffer, bfr->iova);

	bfr->buffer = NULL;
	bfr->iomem = NULL;
	bfr->iova = 0;
	bfr->size = 0;
	bfr->is_mapped = false;
}

static void apple_rtkit_memcpy(struct apple_rtkit *rtk, void *dst,
			       struct apple_rtkit_shmem *bfr, size_t offset,
			       size_t len)
{
	if (bfr->iomem)
		memcpy_fromio(dst, bfr->iomem + offset, len);
	else
		memcpy(dst, bfr->buffer + offset, len);
}

static void apple_rtkit_crashlog_rx(struct apple_rtkit *rtk, u64 msg)
{
	u8 type = FIELD_GET(APPLE_RTKIT_SYSLOG_TYPE, msg);
	u8 *bfr __free(kfree) = NULL;

	if (type != APPLE_RTKIT_CRASHLOG_CRASH) {
		dev_warn(rtk->dev, "RTKit: Unknown crashlog message: %llx\n",
			 msg);
		return;
	}

	if (!rtk->crashlog_buffer.size) {
		apple_rtkit_common_rx_get_buffer(rtk, &rtk->crashlog_buffer,
						 APPLE_RTKIT_EP_CRASHLOG, msg);
		return;
	}

	dev_err(rtk->dev, "RTKit: co-processor has crashed\n");

	/*
	 * create a shadow copy here to make sure the co-processor isn't able
	 * to change the log while we're dumping it. this also ensures
	 * the buffer is in normal memory and not iomem for e.g. the SMC
	 */
	bfr = kzalloc(rtk->crashlog_buffer.size, GFP_KERNEL);
	if (bfr) {
		apple_rtkit_memcpy(rtk, bfr, &rtk->crashlog_buffer, 0,
				   rtk->crashlog_buffer.size);
		apple_rtkit_crashlog_dump(rtk, bfr, rtk->crashlog_buffer.size);
	} else {
		dev_err(rtk->dev,
			"RTKit: Couldn't allocate crashlog shadow buffer\n");
	}

	rtk->crashed = true;
	if (rtk->ops->crashed)
		rtk->ops->crashed(rtk->cookie, bfr, bfr ? rtk->crashlog_buffer.size : 0);
}

static void apple_rtkit_ioreport_rx(struct apple_rtkit *rtk, u64 msg)
{
	u8 type = FIELD_GET(APPLE_RTKIT_SYSLOG_TYPE, msg);

	switch (type) {
	case APPLE_RTKIT_BUFFER_REQUEST:
		apple_rtkit_common_rx_get_buffer(rtk, &rtk->ioreport_buffer,
						 APPLE_RTKIT_EP_IOREPORT, msg);
		break;
	/* unknown, must be ACKed or the co-processor will hang */
	case 0x8:
	case 0xc:
		apple_rtkit_send_message(rtk, APPLE_RTKIT_EP_IOREPORT, msg,
					 NULL, false);
		break;
	default:
		dev_warn(rtk->dev, "RTKit: Unknown ioreport message: %llx\n",
			 msg);
	}
}

static void apple_rtkit_syslog_rx_init(struct apple_rtkit *rtk, u64 msg)
{
	rtk->syslog_n_entries = FIELD_GET(APPLE_RTKIT_SYSLOG_N_ENTRIES, msg);
	rtk->syslog_msg_size = FIELD_GET(APPLE_RTKIT_SYSLOG_MSG_SIZE, msg);

	rtk->syslog_msg_buffer = kzalloc(rtk->syslog_msg_size, GFP_KERNEL);

	dev_dbg(rtk->dev,
		"RTKit: syslog initialized: entries: %zd, msg_size: %zd\n",
		rtk->syslog_n_entries, rtk->syslog_msg_size);
}

static bool should_crop_syslog_char(char c)
{
	return c == '\n' || c == '\r' || c == ' ' || c == '\0';
}

static void apple_rtkit_syslog_rx_log(struct apple_rtkit *rtk, u64 msg)
{
	u8 idx = msg & 0xff;
	char log_context[24];
	size_t entry_size = 0x20 + rtk->syslog_msg_size;
	int msglen;

	if (!rtk->syslog_msg_buffer) {
		dev_warn(
			rtk->dev,
			"RTKit: received syslog message but no syslog_msg_buffer\n");
		goto done;
	}
	if (!rtk->syslog_buffer.size) {
		dev_warn(
			rtk->dev,
			"RTKit: received syslog message but syslog_buffer.size is zero\n");
		goto done;
	}
	if (!rtk->syslog_buffer.buffer && !rtk->syslog_buffer.iomem) {
		dev_warn(
			rtk->dev,
			"RTKit: received syslog message but no syslog_buffer.buffer or syslog_buffer.iomem\n");
		goto done;
	}
	if (idx > rtk->syslog_n_entries) {
		dev_warn(rtk->dev, "RTKit: syslog index %d out of range\n",
			 idx);
		goto done;
	}

	apple_rtkit_memcpy(rtk, log_context, &rtk->syslog_buffer,
			   idx * entry_size + 8, sizeof(log_context));
	apple_rtkit_memcpy(rtk, rtk->syslog_msg_buffer, &rtk->syslog_buffer,
			   idx * entry_size + 8 + sizeof(log_context),
			   rtk->syslog_msg_size);

	log_context[sizeof(log_context) - 1] = 0;

	msglen = strnlen(rtk->syslog_msg_buffer, rtk->syslog_msg_size - 1);
	while (msglen > 0 &&
		   should_crop_syslog_char(rtk->syslog_msg_buffer[msglen - 1]))
		msglen--;

	rtk->syslog_msg_buffer[msglen] = 0;
	dev_info(rtk->dev, "RTKit: syslog message: %s: %s\n", log_context,
		 rtk->syslog_msg_buffer);

done:
	apple_rtkit_send_message(rtk, APPLE_RTKIT_EP_SYSLOG, msg, NULL, false);
}

static void apple_rtkit_syslog_rx(struct apple_rtkit *rtk, u64 msg)
{
	u8 type = FIELD_GET(APPLE_RTKIT_SYSLOG_TYPE, msg);

	switch (type) {
	case APPLE_RTKIT_BUFFER_REQUEST:
		apple_rtkit_common_rx_get_buffer(rtk, &rtk->syslog_buffer,
						 APPLE_RTKIT_EP_SYSLOG, msg);
		break;
	case APPLE_RTKIT_SYSLOG_INIT:
		apple_rtkit_syslog_rx_init(rtk, msg);
		break;
	case APPLE_RTKIT_SYSLOG_LOG:
		apple_rtkit_syslog_rx_log(rtk, msg);
		break;
	default:
		dev_warn(rtk->dev, "RTKit: Unknown syslog message: %llx\n",
			 msg);
	}
}

static void apple_rtkit_oslog_rx(struct apple_rtkit *rtk, u64 msg)
{
	u8 type = FIELD_GET(APPLE_RTKIT_OSLOG_TYPE, msg);

	switch (type) {
	case APPLE_RTKIT_OSLOG_BUFFER_REQUEST:
		apple_rtkit_common_rx_get_buffer(rtk, &rtk->oslog_buffer,
						 APPLE_RTKIT_EP_OSLOG, msg);
		break;
	default:
		dev_warn(rtk->dev, "RTKit: Unknown oslog message: %llx\n",
			 msg);
	}
}

static void apple_rtkit_rx_work(struct work_struct *work)
{
	struct apple_rtkit_rx_work *rtk_work =
		container_of(work, struct apple_rtkit_rx_work, work);
	struct apple_rtkit *rtk = rtk_work->rtk;

	switch (rtk_work->ep) {
	case APPLE_RTKIT_EP_MGMT:
		apple_rtkit_management_rx(rtk, rtk_work->msg);
		break;
	case APPLE_RTKIT_EP_CRASHLOG:
		apple_rtkit_crashlog_rx(rtk, rtk_work->msg);
		break;
	case APPLE_RTKIT_EP_SYSLOG:
		apple_rtkit_syslog_rx(rtk, rtk_work->msg);
		break;
	case APPLE_RTKIT_EP_IOREPORT:
		apple_rtkit_ioreport_rx(rtk, rtk_work->msg);
		break;
	case APPLE_RTKIT_EP_OSLOG:
		apple_rtkit_oslog_rx(rtk, rtk_work->msg);
		break;
	case APPLE_RTKIT_APP_ENDPOINT_START ... 0xff:
		if (rtk->ops->recv_message)
			rtk->ops->recv_message(rtk->cookie, rtk_work->ep,
					       rtk_work->msg);
		else
			dev_warn(
				rtk->dev,
				"Received unexpected message to EP%02d: %llx\n",
				rtk_work->ep, rtk_work->msg);
		break;
	default:
		dev_warn(rtk->dev,
			 "RTKit: message to unknown endpoint %02x: %llx\n",
			 rtk_work->ep, rtk_work->msg);
	}

	kfree(rtk_work);
}

static void apple_rtkit_rx(struct apple_mbox *mbox, struct apple_mbox_msg msg,
			   void *cookie)
{
	struct apple_rtkit *rtk = cookie;
	struct apple_rtkit_rx_work *work;
	u8 ep = msg.msg1;

	/*
	 * The message was read from a MMIO FIFO and we have to make
	 * sure all reads from buffers sent with that message happen
	 * afterwards.
	 */
	dma_rmb();

	if (!test_bit(ep, rtk->endpoints))
		dev_warn(rtk->dev,
			 "RTKit: Message to undiscovered endpoint 0x%02x\n",
			 ep);

	if (ep >= APPLE_RTKIT_APP_ENDPOINT_START &&
	    rtk->ops->recv_message_early &&
	    rtk->ops->recv_message_early(rtk->cookie, ep, msg.msg0))
		return;

	work = kzalloc_obj(*work, GFP_ATOMIC);
	if (!work)
		return;

	work->rtk = rtk;
	work->ep = ep;
	work->msg = msg.msg0;
	INIT_WORK(&work->work, apple_rtkit_rx_work);
	queue_work(rtk->wq, &work->work);
}

int apple_rtkit_send_message(struct apple_rtkit *rtk, u8 ep, u64 message,
			     struct completion *completion, bool atomic)
{
	struct apple_mbox_msg msg = {
		.msg0 = message,
		.msg1 = ep,
	};

	if (rtk->crashed) {
		dev_warn(rtk->dev,
			 "RTKit: Device is crashed, cannot send message\n");
		return -EINVAL;
	}

	if (ep >= APPLE_RTKIT_APP_ENDPOINT_START &&
	    !apple_rtkit_is_running(rtk)) {
		dev_warn(rtk->dev,
			 "RTKit: Endpoint 0x%02x is not running, cannot send message\n", ep);
		return -EINVAL;
	}

	/*
	 * The message will be sent with a MMIO write. We need the barrier
	 * here to ensure any previous writes to buffers are visible to the
	 * device before that MMIO write happens.
	 */
	dma_wmb();

	return apple_mbox_send(rtk->mbox, msg, atomic);
}
EXPORT_SYMBOL_GPL(apple_rtkit_send_message);

static int apple_rtkit_set_ap_power_state(struct apple_rtkit *rtk,
					  unsigned int state);

/*
 * The AP's power state as a coprocessor that keeps running through a system
 * sleep hears it (aurora): idle before the sleep, on after the wake. The noirq
 * variant polls its wait, for the device suspend's noirq phase.
 */
int apple_rtkit_ap_power(struct apple_rtkit *rtk, bool on)
{
	return apple_rtkit_set_ap_power_state(rtk, on ? APPLE_RTKIT_PWR_STATE_ON :
						    APPLE_RTKIT_PWR_STATE_IDLE);
}
EXPORT_SYMBOL_GPL(apple_rtkit_ap_power);

int apple_rtkit_ap_power_noirq(struct apple_rtkit *rtk, bool on)
{
	int ret;

	WRITE_ONCE(rtk->poll_waits, true);
	ret = apple_rtkit_ap_power(rtk, on);
	WRITE_ONCE(rtk->poll_waits, false);

	return ret;
}
EXPORT_SYMBOL_GPL(apple_rtkit_ap_power_noirq);

int apple_rtkit_poll(struct apple_rtkit *rtk)
{
	return apple_mbox_poll(rtk->mbox);
}
EXPORT_SYMBOL_GPL(apple_rtkit_poll);

bool apple_rtkit_has_endpoint(struct apple_rtkit *rtk, u8 ep)
{
	return test_bit(ep, rtk->endpoints);
}
EXPORT_SYMBOL_GPL(apple_rtkit_has_endpoint);

int apple_rtkit_start_ep(struct apple_rtkit *rtk, u8 endpoint)
{
	u64 msg;

	if (!test_bit(endpoint, rtk->endpoints))
		return -EINVAL;
	if (endpoint >= APPLE_RTKIT_APP_ENDPOINT_START &&
	    !apple_rtkit_is_running(rtk))
		return -EINVAL;

	msg = FIELD_PREP(APPLE_RTKIT_MGMT_STARTEP_EP, endpoint);
	msg |= APPLE_RTKIT_MGMT_STARTEP_FLAG;
	apple_rtkit_management_send(rtk, APPLE_RTKIT_MGMT_STARTEP, msg);

	return 0;
}
EXPORT_SYMBOL_GPL(apple_rtkit_start_ep);

struct apple_rtkit *apple_rtkit_init(struct device *dev, void *cookie,
					    const char *mbox_name, int mbox_idx,
					    const struct apple_rtkit_ops *ops)
{
	struct apple_rtkit *rtk;
	int ret;

	if (!ops)
		return ERR_PTR(-EINVAL);

	rtk = kzalloc_obj(*rtk);
	if (!rtk)
		return ERR_PTR(-ENOMEM);

	rtk->dev = dev;
	rtk->cookie = cookie;
	rtk->ops = ops;
	rtk->handshake_timeout_ms = APPLE_RTKIT_HANDSHAKE_TIMEOUT_MS;
	rtk->warm_last_mask = U32_MAX;

	init_completion(&rtk->epmap_completion);
	init_completion(&rtk->iop_pwr_ack_completion);
	init_completion(&rtk->ap_pwr_ack_completion);

	bitmap_zero(rtk->endpoints, APPLE_RTKIT_MAX_ENDPOINTS);
	set_bit(APPLE_RTKIT_EP_MGMT, rtk->endpoints);

	if (mbox_name)
		rtk->mbox = apple_mbox_get_byname(dev, mbox_name);
	else
		rtk->mbox = apple_mbox_get(dev, mbox_idx);

	if (IS_ERR(rtk->mbox)) {
		ret = PTR_ERR(rtk->mbox);
		goto free_rtk;
	}

	rtk->mbox->rx = apple_rtkit_rx;
	rtk->mbox->cookie = rtk;

	rtk->wq = alloc_ordered_workqueue("rtkit-%s", WQ_HIGHPRI | WQ_MEM_RECLAIM,
					  dev_name(rtk->dev));
	if (!rtk->wq) {
		ret = -ENOMEM;
		goto free_rtk;
	}

	ret = apple_mbox_start(rtk->mbox);
	if (ret)
		goto destroy_wq;

	return rtk;

destroy_wq:
	destroy_workqueue(rtk->wq);
free_rtk:
	kfree(rtk);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(apple_rtkit_init);

void apple_rtkit_set_handshake_timeout(struct apple_rtkit *rtk,
				       unsigned int timeout_ms)
{
	rtk->handshake_timeout_ms = timeout_ms ?: APPLE_RTKIT_HANDSHAKE_TIMEOUT_MS;
}
EXPORT_SYMBOL_GPL(apple_rtkit_set_handshake_timeout);

static int apple_rtkit_wait_for_completion(struct apple_rtkit *rtk, struct completion *c)
{
	long t;

	/*
	 * As aurora's apple_rtkit_wait() for poll_waits: poll the mailbox, then
	 * wait 10 ms for the reply, which the (non-freezable) RTKit workqueue
	 * handles as usual, until the handshake timeout.
	 */
	if (READ_ONCE(rtk->poll_waits)) {
		unsigned long timeout = jiffies + msecs_to_jiffies(rtk->handshake_timeout_ms);
		int ret;

		do {
			ret = apple_rtkit_poll(rtk);
			if (ret < 0)
				return ret;
			if (wait_for_completion_timeout(c, msecs_to_jiffies(10)))
				return 0;
		} while (time_before(jiffies, timeout));

		/* Completed after the last wait, before the deadline check. */
		return try_wait_for_completion(c) ? 0 : -ETIME;
	}

	t = wait_for_completion_interruptible_timeout(c,
						      msecs_to_jiffies(rtk->handshake_timeout_ms));
	if (t < 0)
		return t;
	else if (t == 0)
		return -ETIME;
	else
		return 0;
}

int apple_rtkit_reinit(struct apple_rtkit *rtk)
{
	unsigned long flags;

	/* make sure we don't handle any messages while reinitializing */
	apple_mbox_stop(rtk->mbox);
	flush_workqueue(rtk->wq);

	apple_rtkit_free_buffer(rtk, &rtk->ioreport_buffer);
	apple_rtkit_free_buffer(rtk, &rtk->crashlog_buffer);
	apple_rtkit_free_buffer(rtk, &rtk->oslog_buffer);
	apple_rtkit_free_buffer(rtk, &rtk->syslog_buffer);

	kfree(rtk->syslog_msg_buffer);

	rtk->syslog_msg_buffer = NULL;
	rtk->syslog_n_entries = 0;
	rtk->syslog_msg_size = 0;

	bitmap_zero(rtk->endpoints, APPLE_RTKIT_MAX_ENDPOINTS);
	set_bit(APPLE_RTKIT_EP_MGMT, rtk->endpoints);

	reinit_completion(&rtk->epmap_completion);
	reinit_completion(&rtk->iop_pwr_ack_completion);
	reinit_completion(&rtk->ap_pwr_ack_completion);

	rtk->crashed = false;
	rtk->warm_session = false;
	/* A cold boot after a warm restart or sleep stop: the full EPMAP reply, and a receive callback again */
	rtk->warm_restart = false;
	rtk->warm_last_mask = U32_MAX;
	spin_lock_irqsave(&rtk->mbox->rx_lock, flags);
	rtk->mbox->rx = apple_rtkit_rx;
	spin_unlock_irqrestore(&rtk->mbox->rx_lock, flags);
	rtk->iop_power_state = APPLE_RTKIT_PWR_STATE_OFF;
	rtk->ap_power_state = APPLE_RTKIT_PWR_STATE_OFF;

	return apple_mbox_start(rtk->mbox);
}
EXPORT_SYMBOL_GPL(apple_rtkit_reinit);

static int apple_rtkit_set_ap_power_state(struct apple_rtkit *rtk,
					  unsigned int state)
{
	u64 msg;
	int ret;

	reinit_completion(&rtk->ap_pwr_ack_completion);

	msg = FIELD_PREP(APPLE_RTKIT_MGMT_PWR_STATE, state);
	ret = apple_rtkit_management_send(rtk, APPLE_RTKIT_MGMT_SET_AP_PWR_STATE,
					  msg);
	if (ret)
		return ret;

	ret = apple_rtkit_wait_for_completion(rtk, &rtk->ap_pwr_ack_completion);
	if (ret)
		return ret;

	if (rtk->ap_power_state != state)
		return -EINVAL;
	return 0;
}

static int apple_rtkit_set_iop_power_state(struct apple_rtkit *rtk,
					   unsigned int state)
{
	u64 msg;
	int ret;

	reinit_completion(&rtk->iop_pwr_ack_completion);

	msg = FIELD_PREP(APPLE_RTKIT_MGMT_PWR_STATE, state);
	ret = apple_rtkit_management_send(rtk, APPLE_RTKIT_MGMT_SET_IOP_PWR_STATE,
					  msg);
	if (ret)
		return ret;

	ret = apple_rtkit_wait_for_completion(rtk, &rtk->iop_pwr_ack_completion);
	if (ret)
		return ret;

	if (rtk->iop_power_state != state)
		return -EINVAL;
	return 0;
}

int apple_rtkit_boot(struct apple_rtkit *rtk)
{
	/* Bench (note 77 §14.20, review 8 §3): the steps' times, printed with a raised timeout or a failed AP ON. */
	bool report = rtk->handshake_timeout_ms != APPLE_RTKIT_HANDSHAKE_TIMEOUT_MS;
	ktime_t t0 = ktime_get(), t1, t2;
	int ret;

	if (apple_rtkit_is_running(rtk))
		return 0;
	if (rtk->crashed)
		return -EINVAL;

	dev_dbg(rtk->dev, "RTKit: waiting for boot to finish\n");
	ret = apple_rtkit_wait_for_completion(rtk, &rtk->epmap_completion);
	if (ret)
		return ret;
	if (rtk->boot_result)
		return rtk->boot_result;

	dev_dbg(rtk->dev, "RTKit: waiting for IOP power state ACK\n");
	ret = apple_rtkit_wait_for_completion(rtk, &rtk->iop_pwr_ack_completion);
	if (ret)
		return ret;

	t1 = ktime_get();
	ret = apple_rtkit_set_ap_power_state(rtk, APPLE_RTKIT_PWR_STATE_ON);
	t2 = ktime_get();
	if (ret)
		dev_err(rtk->dev, "RTKit: AP power ON failed: %d after %lld ms (map and IOP ack took %lld ms, timeout %u ms)\n",
			ret, ktime_ms_delta(t2, t1), ktime_ms_delta(t1, t0), rtk->handshake_timeout_ms);
	else if (report)
		dev_info(rtk->dev, "RTKit: AP power ON acked after %lld ms (map and IOP ack took %lld ms, timeout %u ms)\n",
			 ktime_ms_delta(t2, t1), ktime_ms_delta(t1, t0), rtk->handshake_timeout_ms);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_rtkit_boot);

int apple_rtkit_shutdown(struct apple_rtkit *rtk)
{
	int ret;

	/* if OFF is used here the co-processor will not wake up again */
	ret = apple_rtkit_set_ap_power_state(rtk,
					     APPLE_RTKIT_PWR_STATE_QUIESCED);
	if (ret)
		return ret;

	ret = apple_rtkit_set_iop_power_state(rtk, APPLE_RTKIT_PWR_STATE_SLEEP);
	if (ret)
		return ret;

	return apple_rtkit_reinit(rtk);
}
EXPORT_SYMBOL_GPL(apple_rtkit_shutdown);

int apple_rtkit_poweroff(struct apple_rtkit *rtk)
{
	int ret;

	ret = apple_rtkit_set_ap_power_state(rtk, APPLE_RTKIT_PWR_STATE_OFF);
	if (ret)
		return ret;

	ret = apple_rtkit_set_iop_power_state(rtk, APPLE_RTKIT_PWR_STATE_OFF);
	if (ret)
		return ret;

	return apple_rtkit_reinit(rtk);
}
EXPORT_SYMBOL_GPL(apple_rtkit_poweroff);

int apple_rtkit_idle(struct apple_rtkit *rtk)
{
	int ret;

	/* if OFF is used here the co-processor will not wake up again */
	ret = apple_rtkit_set_ap_power_state(rtk,
					     APPLE_RTKIT_PWR_STATE_IDLE);
	if (ret)
		return ret;

	ret = apple_rtkit_set_iop_power_state(rtk, APPLE_RTKIT_PWR_STATE_IDLE);
	if (ret)
		return ret;

	rtk->iop_power_state = APPLE_RTKIT_PWR_STATE_IDLE;
	rtk->ap_power_state = APPLE_RTKIT_PWR_STATE_IDLE;
	return 0;
}
EXPORT_SYMBOL_GPL(apple_rtkit_idle);

/*
 * A coprocessor's sleep with its session kept (aurora, by function), for the
 * drivers that ask for it; nothing else changes. The firmware is idled (AP
 * and IOP 0x201), its CPU waited for down, the mailbox stopped and the CPU
 * stopped; after the wake the session is restarted warm, keeping its
 * endpoints and buffers, and the CPU run again.
 */
static void apple_rtkit_detach_rx(struct apple_rtkit *rtk)
{
	unsigned long flags;

	apple_mbox_stop(rtk->mbox);
	spin_lock_irqsave(&rtk->mbox->rx_lock, flags);
	if (rtk->mbox->cookie == rtk)
		rtk->mbox->rx = NULL;
	spin_unlock_irqrestore(&rtk->mbox->rx_lock, flags);
}

void apple_rtkit_mailbox_off(struct apple_rtkit *rtk)
{
	apple_rtkit_detach_rx(rtk);
	flush_workqueue(rtk->wq);
}
EXPORT_SYMBOL_GPL(apple_rtkit_mailbox_off);

void apple_rtkit_set_warm_epmap_mask(struct apple_rtkit *rtk, u32 last_mask)
{
	rtk->warm_last_mask = last_mask;
}
EXPORT_SYMBOL_GPL(apple_rtkit_set_warm_epmap_mask);

int apple_rtkit_warm_restart(struct apple_rtkit *rtk)
{
	unsigned long flags;
	int ret;

	apple_rtkit_detach_rx(rtk);
	flush_workqueue(rtk->wq);

	reinit_completion(&rtk->epmap_completion);
	reinit_completion(&rtk->iop_pwr_ack_completion);
	reinit_completion(&rtk->ap_pwr_ack_completion);

	rtk->crashed = false;
	rtk->warm_restart = true;
	rtk->warm_session = true;
	rtk->iop_power_state = APPLE_RTKIT_PWR_STATE_OFF;
	rtk->ap_power_state = APPLE_RTKIT_PWR_STATE_OFF;

	spin_lock_irqsave(&rtk->mbox->rx_lock, flags);
	rtk->mbox->rx = apple_rtkit_rx;
	spin_unlock_irqrestore(&rtk->mbox->rx_lock, flags);

	ret = apple_mbox_start(rtk->mbox);
	if (ret) {
		rtk->warm_restart = false;
		apple_rtkit_detach_rx(rtk);
		flush_workqueue(rtk->wq);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(apple_rtkit_warm_restart);

static int apple_rtkit_sleep_idle(struct apple_rtkit *rtk, void __iomem *cpu_control)
{
	u32 status;
	int ret;

	ret = apple_rtkit_idle(rtk);
	if (ret)
		return ret;

	ret = readl_poll_timeout(cpu_control + APPLE_ASC_CPU_STATUS, status,
				 (status & APPLE_ASC_CPU_STATUS_DOWN) == APPLE_ASC_CPU_STATUS_DOWN,
				 100, 5000);
	/* Both idles took, so it doesn't run on: stop it as if the status had shown it. */
	if (ret)
		dev_warn(rtk->dev, "RTKit: idle, but not stopped: status %#x\n", status);

	return 0;
}

int apple_rtkit_sleep_stop(struct apple_rtkit *rtk, void __iomem *cpu_control)
{
	int ret;

	ret = apple_rtkit_sleep_idle(rtk, cpu_control);
	if (ret)
		return ret;

	apple_rtkit_mailbox_off(rtk);

	/* Twice, each time from what it reads back. */
	writel(readl(cpu_control) & ~APPLE_ASC_CPU_CONTROL_RUN, cpu_control);
	writel(readl(cpu_control) & ~APPLE_ASC_CPU_CONTROL_RUN, cpu_control);

	return 0;
}
EXPORT_SYMBOL_GPL(apple_rtkit_sleep_stop);

int apple_rtkit_sleep_return(struct apple_rtkit *rtk, void __iomem *cpu_control)
{
	int ret;

	/*
	 * No real sleep: a firmware that idled doesn't come back from that with
	 * its power kept, and stays down until the next sleep restarts it. One
	 * whose idle failed still runs.
	 */
	if (!pm_resume_via_firmware()) {
		if (!(readl(cpu_control) & APPLE_ASC_CPU_CONTROL_RUN) ||
		    (rtk->iop_power_state & 0xff) != APPLE_RTKIT_PWR_STATE_ON)
			return -EAGAIN;
		/* Its AP idle took and its IOP idle didn't: endpoints stay shut until AP on. */
		if ((rtk->ap_power_state & 0xff) != APPLE_RTKIT_PWR_STATE_ON)
			return apple_rtkit_ap_power(rtk, true);
		return 0;
	}

	ret = apple_rtkit_warm_restart(rtk);
	if (ret)
		return ret;

	writel(readl(cpu_control) | APPLE_ASC_CPU_CONTROL_RUN, cpu_control);

	return apple_rtkit_boot(rtk);
}
EXPORT_SYMBOL_GPL(apple_rtkit_sleep_return);

int apple_rtkit_power_cycled_return(struct apple_rtkit *rtk, void __iomem *cpu_control)
{
	int ret = apple_rtkit_warm_restart(rtk);

	if (ret)
		return ret;
	writel(readl(cpu_control) | APPLE_ASC_CPU_CONTROL_RUN, cpu_control);

	return apple_rtkit_boot(rtk);
}
EXPORT_SYMBOL_GPL(apple_rtkit_power_cycled_return);

/*
 * A coprocessor's idle with interrupts off (aurora, by function), for the
 * callers that ask: the receive callback is swapped for one that takes only
 * what an idle needs, the mailbox polled, and the state acks waited on in
 * 10 us steps. Asahi's RTKit echoes no OSLOG counters, so none is owed here.
 */
#define APPLE_RTKIT_POLLED_STEP_US	10
#define APPLE_RTKIT_POLLED_LOOPS	20000

static bool apple_rtkit_notification_msg(u8 ep, u64 msg)
{
	u8 type = FIELD_GET(APPLE_RTKIT_SYSLOG_TYPE, msg);

	if (ep == APPLE_RTKIT_EP_SYSLOG)
		return type == APPLE_RTKIT_SYSLOG_LOG;
	if (ep == APPLE_RTKIT_EP_IOREPORT)
		return type == 0x8 || type == 0xc;
	return false;
}

/* The state acks, and notifications answered as they come (their log unread). */
static void apple_rtkit_polled_rx(struct apple_mbox *mbox, struct apple_mbox_msg msg, void *cookie)
{
	struct apple_rtkit *rtk = cookie;
	u8 ep = msg.msg1;

	if (ep == APPLE_RTKIT_EP_MGMT) {
		u8 type = FIELD_GET(APPLE_RTKIT_MGMT_TYPE, msg.msg0);
		unsigned int state = FIELD_GET(APPLE_RTKIT_MGMT_PWR_STATE, msg.msg0);

		if (type == APPLE_RTKIT_MGMT_SET_IOP_PWR_STATE_ACK)
			WRITE_ONCE(rtk->iop_power_state, state);
		else if (type == APPLE_RTKIT_MGMT_SET_AP_PWR_STATE_ACK)
			WRITE_ONCE(rtk->ap_power_state, state);
	} else if (apple_rtkit_notification_msg(ep, msg.msg0)) {
		apple_mbox_send(mbox, msg, true);
	}
}

static int apple_rtkit_polled_state(struct apple_rtkit *rtk, u8 type, unsigned int *state,
				    unsigned int *us)
{
	struct apple_mbox_msg msg = {
		.msg0 = FIELD_PREP(APPLE_RTKIT_MGMT_TYPE, type) |
			FIELD_PREP(APPLE_RTKIT_MGMT_PWR_STATE, APPLE_RTKIT_PWR_STATE_IDLE),
		.msg1 = APPLE_RTKIT_EP_MGMT,
	};
	int i, ret;

	ret = apple_mbox_send(rtk->mbox, msg, true);
	if (ret)
		return ret;

	for (i = 0; i < APPLE_RTKIT_POLLED_LOOPS; i++) {
		apple_mbox_poll(rtk->mbox);
		if (READ_ONCE(*state) == APPLE_RTKIT_PWR_STATE_IDLE)
			return 0;
		udelay(APPLE_RTKIT_POLLED_STEP_US);
		*us += APPLE_RTKIT_POLLED_STEP_US;
	}

	return -ETIMEDOUT;
}

static void apple_rtkit_polled_begin(struct apple_rtkit *rtk)
{
	unsigned long flags;

	spin_lock_irqsave(&rtk->mbox->rx_lock, flags);
	rtk->mbox->rx = apple_rtkit_polled_rx;
	spin_unlock_irqrestore(&rtk->mbox->rx_lock, flags);

	/* What's already waiting is answered first, or the firmware may not go idle. */
	apple_mbox_poll(rtk->mbox);
}

static void apple_rtkit_polled_end(struct apple_rtkit *rtk)
{
	unsigned long flags;

	spin_lock_irqsave(&rtk->mbox->rx_lock, flags);
	rtk->mbox->rx = apple_rtkit_rx;
	spin_unlock_irqrestore(&rtk->mbox->rx_lock, flags);
}

int apple_rtkit_sleep_idle_polled(struct apple_rtkit *rtk, void __iomem *cpu_control,
				  unsigned int *us)
{
	u32 status;
	int ret;

	*us = 0;
	apple_rtkit_polled_begin(rtk);

	ret = apple_rtkit_polled_state(rtk, APPLE_RTKIT_MGMT_SET_AP_PWR_STATE,
				       &rtk->ap_power_state, us);
	if (!ret)
		ret = apple_rtkit_polled_state(rtk, APPLE_RTKIT_MGMT_SET_IOP_PWR_STATE,
					       &rtk->iop_power_state, us);
	if (!ret)
		ret = readl_poll_timeout_atomic(cpu_control + APPLE_ASC_CPU_STATUS, status,
						(status & APPLE_ASC_CPU_STATUS_DOWN) ==
						APPLE_ASC_CPU_STATUS_DOWN,
						APPLE_RTKIT_POLLED_STEP_US, 5000);

	apple_rtkit_polled_end(rtk);

	return ret;
}
EXPORT_SYMBOL_GPL(apple_rtkit_sleep_idle_polled);

int apple_rtkit_ap_idle_polled(struct apple_rtkit *rtk, unsigned int *us)
{
	int ret;

	*us = 0;
	apple_rtkit_polled_begin(rtk);
	ret = apple_rtkit_polled_state(rtk, APPLE_RTKIT_MGMT_SET_AP_PWR_STATE,
				       &rtk->ap_power_state, us);
	apple_rtkit_polled_end(rtk);

	return ret;
}
EXPORT_SYMBOL_GPL(apple_rtkit_ap_idle_polled);

int apple_rtkit_quiesce(struct apple_rtkit *rtk)
{
	int ret;

	ret = apple_rtkit_set_ap_power_state(rtk,
					     APPLE_RTKIT_PWR_STATE_QUIESCED);
	if (ret)
		return ret;

	ret = apple_rtkit_set_iop_power_state(rtk,
					      APPLE_RTKIT_PWR_STATE_QUIESCED);
	if (ret)
		return ret;

	ret = apple_rtkit_reinit(rtk);
	if (ret)
		return ret;

	rtk->iop_power_state = APPLE_RTKIT_PWR_STATE_QUIESCED;
	rtk->ap_power_state = APPLE_RTKIT_PWR_STATE_QUIESCED;
	return 0;
}
EXPORT_SYMBOL_GPL(apple_rtkit_quiesce);

int apple_rtkit_wake(struct apple_rtkit *rtk)
{
	u64 msg;
	int ret;

	if (apple_rtkit_is_running(rtk))
		return -EINVAL;

	reinit_completion(&rtk->iop_pwr_ack_completion);

	/*
	 * Use open-coded apple_rtkit_set_iop_power_state since apple_rtkit_boot
	 * will wait for the completion anyway.
	 */
	msg = FIELD_PREP(APPLE_RTKIT_MGMT_PWR_STATE, APPLE_RTKIT_PWR_STATE_INIT);
	ret = apple_rtkit_management_send(rtk, APPLE_RTKIT_MGMT_SET_IOP_PWR_STATE,
					  msg);
	if (ret)
		return ret;

	return apple_rtkit_boot(rtk);
}
EXPORT_SYMBOL_GPL(apple_rtkit_wake);

void apple_rtkit_free(struct apple_rtkit *rtk)
{
	apple_mbox_stop(rtk->mbox);
	destroy_workqueue(rtk->wq);

	apple_rtkit_free_buffer(rtk, &rtk->ioreport_buffer);
	apple_rtkit_free_buffer(rtk, &rtk->crashlog_buffer);
	apple_rtkit_free_buffer(rtk, &rtk->oslog_buffer);
	apple_rtkit_free_buffer(rtk, &rtk->syslog_buffer);

	kfree(rtk->syslog_msg_buffer);
	kfree(rtk);
}
EXPORT_SYMBOL_GPL(apple_rtkit_free);

static void apple_rtkit_free_wrapper(void *data)
{
	apple_rtkit_free(data);
}

struct apple_rtkit *devm_apple_rtkit_init(struct device *dev, void *cookie,
					  const char *mbox_name, int mbox_idx,
					  const struct apple_rtkit_ops *ops)
{
	struct apple_rtkit *rtk;
	int ret;

	rtk = apple_rtkit_init(dev, cookie, mbox_name, mbox_idx, ops);
	if (IS_ERR(rtk))
		return rtk;

	ret = devm_add_action_or_reset(dev, apple_rtkit_free_wrapper, rtk);
	if (ret)
		return ERR_PTR(ret);

	return rtk;
}
EXPORT_SYMBOL_GPL(devm_apple_rtkit_init);

void devm_apple_rtkit_free(struct device *dev, struct apple_rtkit *rtk)
{
	devm_release_action(dev, apple_rtkit_free_wrapper, rtk);
}
EXPORT_SYMBOL_GPL(devm_apple_rtkit_free);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Sven Peter <sven@svenpeter.dev>");
MODULE_DESCRIPTION("Apple RTKit driver");
