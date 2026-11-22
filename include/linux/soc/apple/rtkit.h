/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * Apple RTKit IPC Library
 * Copyright (C) The Asahi Linux Contributors
 *
 * Apple's SoCs come with various co-processors running their RTKit operating
 * system. This protocol library is used by client drivers to use the
 * features provided by them.
 */
#ifndef _LINUX_APPLE_RTKIT_H_
#define _LINUX_APPLE_RTKIT_H_

#include <linux/device.h>
#include <linux/types.h>
#include <linux/mailbox_client.h>

/*
 * Struct to represent implementation-specific RTKit operations.
 *
 * @buffer:    Shared memory buffer allocated inside normal RAM.
 * @iomem:     Shared memory buffer controlled by the co-processors.
 * @size:      Size of the shared memory buffer.
 * @iova:      Device VA of shared memory buffer.
 * @is_mapped: Shared memory buffer is managed by the co-processor.
 * @private:   Private data pointer for the parent driver.
 */

struct apple_rtkit_shmem {
	void *buffer;
	void __iomem *iomem;
	size_t size;
	dma_addr_t iova;
	bool is_mapped;
	void *private;
};

/*
 * Struct to represent implementation-specific RTKit operations.
 *
 * @crashed:       Called when the co-processor has crashed. Runs in process
 *                 context.
 * @recv_message:  Function called when a message from RTKit is received
 *                 on a non-system endpoint. Called from a worker thread.
 * @recv_message_early:
 *                 Like recv_message, but called from atomic context. It
 *                 should return true if it handled the message. If it
 *                 returns false, the message will be passed on to the
 *                 worker thread.
 * @shmem_setup:   Setup shared memory buffer. If bfr.is_iomem is true the
 *                 buffer is managed by the co-processor and needs to be mapped.
 *                 Otherwise the buffer is managed by Linux and needs to be
 *                 allocated. If not specified dma_alloc_coherent is used.
 *                 Called in process context.
 * @shmem_destroy: Undo the shared memory buffer setup in shmem_setup. If not
 *                 specified dma_free_coherent is used. Called in process
 *                 context.
 */
struct apple_rtkit_ops {
	void (*crashed)(void *cookie, const void *crashlog, size_t crashlog_size);
	void (*recv_message)(void *cookie, u8 endpoint, u64 message);
	bool (*recv_message_early)(void *cookie, u8 endpoint, u64 message);
	int (*shmem_setup)(void *cookie, struct apple_rtkit_shmem *bfr);
	void (*shmem_destroy)(void *cookie, struct apple_rtkit_shmem *bfr);
};

struct apple_rtkit;

/*
 * Initializes the internal state required to handle RTKit. This
 * should usually be called within _probe.
 *
 * @dev:         Pointer to the device node this coprocessor is associated with
 * @cookie:      opaque cookie passed to all functions defined in rtkit_ops
 * @mbox_name:   mailbox name used to communicate with the co-processor
 * @mbox_idx:    mailbox index to be used if mbox_name is NULL
 * @ops:         pointer to rtkit_ops to be used for this co-processor
 */
struct apple_rtkit *devm_apple_rtkit_init(struct device *dev, void *cookie,
					  const char *mbox_name, int mbox_idx,
					  const struct apple_rtkit_ops *ops);
/*
 * Frees internal RTKit state allocated by devm_apple_rtkit_init().
 *
 * @dev:	Pointer to the device node this coprocessor is assocated with
 * @rtk:	Internal RTKit state initialized by devm_apple_rtkit_init()
 */
void devm_apple_rtkit_free(struct device *dev, struct apple_rtkit *rtk);

/*
 * Non-devm version of devm_apple_rtkit_init. Must be freed with
 * apple_rtkit_free.
 *
 * @dev:         Pointer to the device node this coprocessor is associated with
 * @cookie:      opaque cookie passed to all functions defined in rtkit_ops
 * @mbox_name:   mailbox name used to communicate with the co-processor
 * @mbox_idx:    mailbox index to be used if mbox_name is NULL
 * @ops:         pointer to rtkit_ops to be used for this co-processor
 */
struct apple_rtkit *apple_rtkit_init(struct device *dev, void *cookie,
					  const char *mbox_name, int mbox_idx,
					  const struct apple_rtkit_ops *ops);

/*
 * Free an instance of apple_rtkit.
 */
void apple_rtkit_free(struct apple_rtkit *rtk);

/*
 * Reinitialize internal structures. Must only be called with the co-processor
 * is held in reset.
 */
int apple_rtkit_reinit(struct apple_rtkit *rtk);

/*
 * Like apple_rtkit_reinit(), for a co-processor put to idle that resumes from its saved context: it keeps the
 * shared buffers it was given, so they stay mapped; only the mailbox and the power handshake restart.
 */
int apple_rtkit_reinit_keep(struct apple_rtkit *rtk);

/* Stop receiving before an idled co-processor sleeps; its buffers stay put. */
void apple_rtkit_detach_keep(struct apple_rtkit *rtk);

/*
 * Set how long each handshake step (power state and endpoint map replies)
 * waits for the co-processor, for one that is known to answer slowly. Call
 * before apple_rtkit_boot(). Zero restores the default of 1000 ms.
 */
void apple_rtkit_set_handshake_timeout(struct apple_rtkit *rtk,
				       unsigned int timeout_ms);

/*
 * Handle RTKit's boot process. Should be called after the CPU of the
 * co-processor has been started.
 */
int apple_rtkit_boot(struct apple_rtkit *rtk);

/*
 * Quiesce the co-processor.
 */
int apple_rtkit_quiesce(struct apple_rtkit *rtk);

/*
 * Wake the co-processor up from hibernation mode.
 */
int apple_rtkit_wake(struct apple_rtkit *rtk);

/*
 * Shutdown the co-processor
 */
int apple_rtkit_shutdown(struct apple_rtkit *rtk);

/*
 * Put the co-processor into the lowest power state. Note that it usually
 * is not possible to recover from this state without a full SoC reset.
 */

int apple_rtkit_poweroff(struct apple_rtkit *rtk);

/*
 * Put the co-processor into idle mode
 */
int apple_rtkit_idle(struct apple_rtkit *rtk);

/*
 * Checks if RTKit is running and ready to handle messages.
 */
bool apple_rtkit_is_running(struct apple_rtkit *rtk);

/*
 * Checks if RTKit has crashed.
 */
bool apple_rtkit_is_crashed(struct apple_rtkit *rtk);

/*
 * Starts an endpoint. Must be called after boot but before any messages can be
 * sent or received from that endpoint.
 */
int apple_rtkit_start_ep(struct apple_rtkit *rtk, u8 endpoint);

/*
 * Send a message to the given endpoint.
 *
 * @rtk:            RTKit reference
 * @ep:             target endpoint
 * @message:        message to be sent
 * @completeion:    will be completed once the message has been submitted
 *                  to the hardware FIFO. Can be NULL.
 * @atomic:         if set to true this function can be called from atomic
 *                  context.
 */
int apple_rtkit_send_message(struct apple_rtkit *rtk, u8 ep, u64 message,
			     struct completion *completion, bool atomic);

/*
 * Process incoming messages in atomic context.
 * This only guarantees that messages arrive as far as the recv_message_early
 * callback; drivers expecting to handle incoming messages synchronously
 * by calling this function must do it that way.
 * Will return 1 if some data was processed, 0 if none was, or a
 * negative error code on failure.
 *
 * @rtk:            RTKit reference
 */
int apple_rtkit_poll(struct apple_rtkit *rtk);

/*
 * Tell a coprocessor that keeps running through a system sleep the AP's power
 * state: idle (@on false) before the sleep, on after the wake. The _noirq
 * variant polls for the reply, for the noirq phase.
 */
int apple_rtkit_ap_power(struct apple_rtkit *rtk, bool on);
int apple_rtkit_ap_power_noirq(struct apple_rtkit *rtk, bool on);

/*
 * A coprocessor's sleep with its session kept (aurora): idle it and stop its
 * CPU (@cpu_control is its ASC CPU_CONTROL word); after the wake restart the
 * session warm, keeping its endpoints and buffers, and run the CPU again.
 * power_cycled_return() is the same after its power was cycled without a
 * system sleep. warm_restart() alone restarts the session.
 */
int apple_rtkit_sleep_stop(struct apple_rtkit *rtk, void __iomem *cpu_control);
int apple_rtkit_sleep_return(struct apple_rtkit *rtk, void __iomem *cpu_control);
int apple_rtkit_power_cycled_return(struct apple_rtkit *rtk, void __iomem *cpu_control);
int apple_rtkit_warm_restart(struct apple_rtkit *rtk);
void apple_rtkit_mailbox_off(struct apple_rtkit *rtk);
void apple_rtkit_set_warm_epmap_mask(struct apple_rtkit *rtk, u32 last_mask);

/*
 * With interrupts off (aurora): AP and IOP idle with their acks polled, then
 * the CPU's status waited for down; or only the AP idle notice (0x201), no IOP
 * state, no CPU stop. @us gets the time spent waiting.
 */
int apple_rtkit_sleep_idle_polled(struct apple_rtkit *rtk, void __iomem *cpu_control,
				  unsigned int *us);
int apple_rtkit_ap_idle_polled(struct apple_rtkit *rtk, unsigned int *us);

/* Echo the firmware's OSLOG counters (off by default), as macOS does: a DCP after a warm restart */
void apple_rtkit_set_oslog_echo(struct apple_rtkit *rtk, bool echo);
/* Bench: apple_rtkit_idle() with a timeout per ack and a hook after the AP request */
int apple_rtkit_bench_idle(struct apple_rtkit *rtk, unsigned int timeout_ms,
			   void (*after_ap_send)(void *data), void *data);
void apple_rtkit_bench_states(struct apple_rtkit *rtk, unsigned int *ap, unsigned int *iop);

/*
 * Checks if an endpoint with a given index exists
 *
 * @rtk:            RTKit reference
 * @ep:             endpoint to check for
 */
bool apple_rtkit_has_endpoint(struct apple_rtkit *rtk, u8 ep);

#endif /* _LINUX_APPLE_RTKIT_H_ */
