/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * What drivers tell the code that takes an Apple SoC into a firmware-driven
 * suspend.
 */
#ifndef _LINUX_SOC_APPLE_SLEEP_H_
#define _LINUX_SOC_APPLE_SLEEP_H_

#include <linux/compiler_types.h>
#include <linux/errno.h>
#include <linux/kconfig.h>
#include <linux/types.h>

struct apple_smc;

struct device;
struct device_node;

/*
 * The enclave's stop records what its SLEEP got here, in RAM only, for the bench's table to
 * hand to the hypervisor as guest marks after the stop returns (Tanabota note 27 §6.18).
 */
#define APPLE_SLEEP_ENCLAVE_REPORT_WORDS	3
extern u64 apple_sleep_enclave_report[APPLE_SLEEP_ENCLAVE_REPORT_WORDS];

#if IS_ENABLED(CONFIG_APPLE_SOC_SLEEP)
/*
 * A coprocessor that can't be stopped until a sleep is certain, and can't be
 * restarted without one. While one is registered and not ready, a suspend is
 * refused. Once ready, the last step before the commit runs @last_stop, with
 * interrupts off and every refusal behind it, then clears its run bit. With
 * @pcie_ans, that also lowers the PCIe and ANS domains, which nothing else may do
 * under it. @last_stop can't refuse: a nonzero return means it failed, and the sleep
 * goes on.
 */
int apple_sleep_coproc_register(struct device *dev, void __iomem *asc, bool pcie_ans,
				int (*last_stop)(void *data), void *data);

/*
 * The same with no ASC to clear: @last_stop clears its own run bits and lowers its own power
 * domain, and runs before every other coprocessor's. The refusal checks leave that domain on.
 */
int apple_sleep_coproc_register_first(struct device *dev, int (*last_stop)(void *data),
				      void *data);
void apple_sleep_coproc_unregister(struct device *dev);

/*
 * During a suspend: a driver left something the DRAM-kept wake would stall on, so this
 * sleep takes the deep path. False if no sleep driver can do that.
 */
bool apple_sleep_request_deep_once(void);

/*
 * For a registered coprocessor: the last of its stop that may still refuse the sleep, run
 * with interrupts off before any coprocessor's @last_stop. A negative return refuses, and the
 * coprocessor must still be able to carry on.
 */
int apple_sleep_coproc_set_last_check(struct device *dev, int (*last_check)(void *data));

/*
 * The enclave's irreversible sleep request. @stop runs with interrupts off,
 * after every refusal and before other irreversible coprocessor stops. Nonzero
 * may refuse ONLY if no request was sent. Once sent, protocol failure is fatal;
 * success must continue through physical sleep/wake, even for a newly pending wake.
 * Unsupported/no-provider paths refuse before sending, never at device suspend.
 */
int apple_sleep_enclave_register(struct device *dev, int (*stop)(void *data), void *data);
void apple_sleep_enclave_unregister(struct device *dev);

/* Its driver has quiesced it for that last step, or has taken it back. */
void apple_sleep_coproc_set_ready(struct device *dev, bool ready);

/* Whether the last step stopped it: after a refused sleep, false means it still runs. */
bool apple_sleep_coproc_stopped(struct device *dev);

/*
 * Whether this sleep's commit stops the registered coprocessors. Then one that can't be
 * registered refuses the sleep: stopped any earlier, a later refusal would strand it.
 */
bool apple_sleep_commit_stops_coprocs(void);

/*
 * The USB host sleeps in place for this sleep, as macOS's does: its always-on domain stays
 * up through the commit. Its PHY sets it once the controller is in its hibernation state,
 * and clears it at the wake.
 */
void apple_sleep_usb_set_asleep(bool asleep);

/*
 * The USB host is up, as macOS's USB_SLP_DDR vote has it: from the host's start to its stop,
 * awake and asleep. It sets bit 0 of the wake block's word 0 for every sleep in between.
 */
void apple_sleep_usb_slp_ddr(bool up);

/*
 * The fixed hub's ports with a device at or below them that can wake the system, bit n for
 * port n. The host that sleeps in place sets them before the freeze and clears them after.
 */
void apple_sleep_usb_set_wake_ports(unsigned long ports);

/*
 * For a driver that takes its own power domain down for a sleep and up again, as macOS's USB
 * host does: @pd is the domain's power controller node. Lowering waits until it reads off.
 * 0, -ETIMEDOUT, -ENODEV without the sleep driver, or -EINVAL for another node, which leave
 * the domain alone and which apple_sleep_domain_check() reports beforehand.
 */
int apple_sleep_domain_set(struct device_node *pd, bool on);
int apple_sleep_domain_check(struct device_node *pd);

/* For the PMGR's driver at the wake: a driver took @pd down and brings it up itself. */
bool apple_sleep_domain_is_down(struct device_node *pd);

/* For the port controller wired to the fixed hub's @port, as it arms USB wake. */
bool apple_sleep_usb_port_can_wake(unsigned int port);

/* The last sleep ended the debug link on @dev, whose driver may rearm it. */
bool apple_sleep_debug_link_was_cut(struct device *dev);

/* The same, without taking it: the port controller's own setup after its cold reset. */
bool apple_sleep_debug_link_cut_peek(struct device *dev);

/*
 * End the debug link now, if this sleep hasn't: true if this call did. For the SMC's driver,
 * ahead of its AP idle notice. It takes over a second, and doesn't sleep.
 */
bool apple_sleep_debug_link_cut(void);

/* This sleep will end the debug link: for the SMC's driver, which warns the SMC after it. */
bool apple_sleep_debug_link_up(void);

/*
 * The m1n1 bench's t6020 sleep (apple_sleep.aop_sleep): the AOP takes its sleep (endpoints
 * stopped, the AP idle notice) as in a firmware-driven suspend, which the bench doesn't flag.
 */
bool apple_sleep_bench_aop_sleep(void);
bool apple_sleep_bench_aop_macos_order(void);
/* apple_sleep.hybrid: the drivers' hybrid S3 switches as one mask (note 77 §14.20) */
#define APPLE_SLEEP_HYBRID_SART		BIT(0)
#define APPLE_SLEEP_HYBRID_PINCTRL	BIT(1)
#define APPLE_SLEEP_HYBRID_SPMI		BIT(2)
#define APPLE_SLEEP_HYBRID_AIC		BIT(3)
#define APPLE_SLEEP_HYBRID_DART		BIT(4)
/* the same mask for note 82's switches: passive reads, then one restore each */
#define APPLE_SLEEP_HYBRID_READS	BIT(5)	/* PMP SRAM checksum, pinctrl +0xc48 prints */
#define APPLE_SLEEP_HYBRID_PMP_SRAM	BIT(6)	/* apple_pmp.bench_sram=2 */
#define APPLE_SLEEP_HYBRID_INPUT_EN	BIT(7)	/* pinctrl_apple_gpio.bench_input_enable=3 */
#define APPLE_SLEEP_HYBRID_ANS_KEEP	BIT(8)	/* nvme_apple.bench_reinit_keep=1 */
#define APPLE_SLEEP_HYBRID_DCP_BOOT	BIT(9)	/* a table-stopped DCP restarted in its resume */
#define APPLE_SLEEP_HYBRID_SD_HW	BIT(10)	/* the GL9755's probe setup again in its resume */
#define APPLE_SLEEP_HYBRID_DCP_BOOT2	BIT(11)	/* dcp-boot v2: macOS's restart, the CPU domain cycled */
#define APPLE_SLEEP_HYBRID_DCP_PS_MIN	BIT(12)	/* disp0_cpu0's PS_MIN floor put back in the DCP's resume */
#define APPLE_SLEEP_HYBRID_PCIE_MSI	BIT(13)	/* t602x PCIe ports' MSI doorbell set up again at resume */
#define APPLE_SLEEP_HYBRID_SMC_EDGE	BIT(14)	/* the SMC's sleep keys read after slpw and before slpa (note 84 §36 R2) */
#define APPLE_SLEEP_HYBRID_PS_RESTORE	BIT(15)	/* unowned SIO/peripheral PS words on at .enter raised again at .wake (note 77 §14.128) */
#define APPLE_SLEEP_HYBRID_DCP_EL2	BIT(26)	/* native (EL2): the internal DCP restarted after the cut (task 146) */
u32 apple_sleep_bench_hybrid(void);
/* The SMC's driver, after waka at the wake: true and pmVC's value to write again (smc_notify bit 3) */
bool apple_sleep_bench_pmvc_wake(u32 *value);
/* smc_notify as set, 0 without the sequencer: the SMC driver's wake-time switches are bits 5-7 */
unsigned int apple_sleep_bench_smc_wake_bits(void);
/* apple_sleep.smc_probe: one read-only line of VR3l, MEPS and the PMU's 0x200/0x1300/0x2505, tagged; @polled as the SMC's reads are */
void apple_sleep_bench_probe(struct apple_smc *smc, const char *tag, bool polled);
bool apple_sleep_bench_aop_notices(void);
u32 apple_sleep_bench_aop_quiet(void);

/*
 * The same for the SEP (apple_sleep.sep_sleep): its .suspend stages the SLEEP, the table sends
 * it; a failure after the send refuses the commit instead of the native path's panic.
 */
bool apple_sleep_bench_sep_sleep(void);

/*
 * The early variant (apple_sleep.sep_sleep_early): the SEP's own .suspend sends its SLEEP in
 * process context and waits for the answer; suspend_noirq waits for its domain to gate.
 */
bool apple_sleep_bench_sep_sleep_early(void);
/* The SEP driver that sends the early SLEEP says so; sleep-seq's via_firmware guard asks */
void apple_sleep_sep_early_set(struct device *dev, bool wired);
/* An external DCP's driver stopped it for this sleep, or brought it back */
void apple_sleep_dispext_down(struct device *dev, bool down);
/* The internal DCP's driver bound it (its RTKit up), or unbound it */
void apple_sleep_disp0_bound(bool bound);
/* Its driver's check at .begin: why it won't stop for this sleep, or NULL (NULL @veto unregisters) */
void apple_sleep_dispext_register(struct device *dev,
				  const char *(*veto)(struct device *dev, bool via_firmware));
/* dispext_refuse, with the S2R entry: whether its driver refuses a sleep it couldn't stop for */
bool apple_sleep_dispext_refuses(void);
bool apple_sleep_sep_early_wired(void);
/* The SEP driver's sleep gate for the entry crumb: 0 open, 1 draining, 2 told, 3 lost, 4 refused */
void apple_sleep_sep_gate_set(u8 gate);
/*
 * The PMP driver's sleep state for the bench's crumbs: 0 not registered, 1 registered but
 * not asked to stop (no firmware sleep, no bench_sleep), 2 stopped at suspend_late, 3 its
 * stop failed, 4 left for the commit, 5 idled at the commit, 6 its commit idle failed
 */
bool apple_sleep_seq_s2r(void);
void apple_sleep_pmp_state_set(u8 state);


/*
 * From the SMC's driver, in its noirq resume: the SMC woke the AP for the lid alone, and the
 * lid reads closed. If nothing else woke the SoC, the PM core goes back to sleep once every
 * device has resumed, as macOS does from a dark wake.
 */
void apple_sleep_lid_closed_wake(void);

/*
 * From the SMC's driver, in its noirq resume: the SMC woke the AP for the port alone. If
 * this sleep cut the debug link and nothing else woke the SoC, it's a dark wake.
 */
void apple_sleep_debug_link_cut_wake(void);

/* The radio's host has its port back after a real sleep, so the next commit may stop it. */
void apple_sleep_radio_port_up(void);

/* From RTKit: this coprocessor's firmware crashed. */
void apple_sleep_coproc_crashed(struct device *dev);

/* After a deep sleep, put back the pins it reset. ANS's driver calls it before the run bit. */
void apple_sleep_restore_pins(void);

/*
 * After a refused sleep, for a firmware that idled on a domain that can't gate alone: the
 * sleep engine's PMGR reset of its own domains, its DARTs kept. The caller starts it after.
 */
int apple_sleep_engine_reset(struct device *dev);
#else
static inline int apple_sleep_coproc_register(struct device *dev, void __iomem *asc,
					      bool pcie_ans, int (*last_stop)(void *data),
					      void *data)
{
	return -EOPNOTSUPP;
}

static inline int apple_sleep_coproc_register_first(struct device *dev,
						    int (*last_stop)(void *data), void *data)
{
	return -EOPNOTSUPP;
}

static inline bool apple_sleep_request_deep_once(void)
{
	return false;
}

static inline void apple_sleep_coproc_unregister(struct device *dev)
{
}

static inline int apple_sleep_coproc_set_last_check(struct device *dev,
						    int (*last_check)(void *data))
{
	return -EOPNOTSUPP;
}

static inline int apple_sleep_enclave_register(struct device *dev, int (*tell)(void *data),
					       void *data)
{
	return -EOPNOTSUPP;
}

static inline void apple_sleep_enclave_unregister(struct device *dev)
{
}

static inline void apple_sleep_coproc_set_ready(struct device *dev, bool ready)
{
}

static inline bool apple_sleep_coproc_stopped(struct device *dev)
{
	return false;
}

static inline bool apple_sleep_commit_stops_coprocs(void)
{
	return false;
}

static inline void apple_sleep_usb_set_asleep(bool asleep)
{
}

static inline void apple_sleep_usb_slp_ddr(bool up)
{
}

static inline void apple_sleep_usb_set_wake_ports(unsigned long ports)
{
}

static inline int apple_sleep_domain_set(struct device_node *pd, bool on)
{
	return -ENODEV;
}

static inline int apple_sleep_domain_check(struct device_node *pd)
{
	return -ENODEV;
}

static inline bool apple_sleep_domain_is_down(struct device_node *pd)
{
	return false;
}

static inline bool apple_sleep_usb_port_can_wake(unsigned int port)
{
	return false;
}

static inline bool apple_sleep_debug_link_was_cut(struct device *dev)
{
	return false;
}

static inline bool apple_sleep_debug_link_cut_peek(struct device *dev)
{
	return false;
}

static inline bool apple_sleep_debug_link_cut(void)
{
	return false;
}

static inline bool apple_sleep_debug_link_up(void)
{
	return false;
}

static inline bool apple_sleep_bench_aop_sleep(void)
{
	return false;
}
static inline void apple_sleep_bench_probe(struct apple_smc *smc, const char *tag, bool polled)
{
}

static inline unsigned int apple_sleep_bench_smc_wake_bits(void)
{
	return 0;
}

static inline bool apple_sleep_bench_pmvc_wake(u32 *value)
{
	return false;
}

static inline u32 apple_sleep_bench_hybrid(void)
{
	return 0;
}
static inline bool apple_sleep_bench_aop_macos_order(void)
{
	return false;
}
static inline bool apple_sleep_bench_aop_notices(void)
{
	return false;
}
static inline u32 apple_sleep_bench_aop_quiet(void)
{
	return 0;
}

static inline bool apple_sleep_bench_sep_sleep(void)
{
	return false;
}

static inline bool apple_sleep_bench_sep_sleep_early(void)
{
	return false;
}

static inline void apple_sleep_sep_early_set(struct device *dev, bool wired)
{
}

static inline void apple_sleep_dispext_down(struct device *dev, bool down)
{
}

static inline void apple_sleep_disp0_bound(bool bound)
{
}

static inline bool apple_sleep_dispext_refuses(void)
{
	return false;
}

static inline void apple_sleep_dispext_register(struct device *dev,
						const char *(*veto)(struct device *dev,
								    bool via_firmware))
{
}

static inline bool apple_sleep_sep_early_wired(void)
{
	return false;
}

static inline void apple_sleep_sep_gate_set(u8 gate)
{
}

static inline bool apple_sleep_seq_s2r(void)
{
	return false;
}

static inline void apple_sleep_pmp_state_set(u8 state)
{
}

static inline void apple_sleep_lid_closed_wake(void)
{
}

static inline void apple_sleep_debug_link_cut_wake(void)
{
}

static inline void apple_sleep_radio_port_up(void)
{
}

static inline void apple_sleep_coproc_crashed(struct device *dev)
{
}

static inline void apple_sleep_restore_pins(void)
{
}

static inline int apple_sleep_engine_reset(struct device *dev)
{
	return -EOPNOTSUPP;
}
#endif

#endif
