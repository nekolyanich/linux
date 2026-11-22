// SPDX-License-Identifier: GPL-2.0
/*
 * PCIe host bridge driver for Apple system-on-chips.
 *
 * The HW is ECAM compliant, so once the controller is initialized,
 * the driver mostly deals MSI mapping and handling of per-port
 * interrupts (INTx, management and error signals).
 *
 * Initialization requires enabling power and clocks, along with a
 * number of register pokes.
 *
 * Copyright (C) 2021 Alyssa Rosenzweig <alyssa@rosenzweig.io>
 * Copyright (C) 2021 Google LLC
 * Copyright (C) 2021 Corellium LLC
 * Copyright (C) 2021 Mark Kettenis <kettenis@openbsd.org>
 *
 * Author: Alyssa Rosenzweig <alyssa@rosenzweig.io>
 * Author: Marc Zyngier <maz@kernel.org>
 */

#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/kernel.h>
#include <linux/iopoll.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/irqchip/irq-msi-lib.h>
#include <linux/irqdomain.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/pci-ecam.h>
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <linux/pm_domain.h>
#include <linux/soc/apple/dart.h>
#include <linux/soc/apple/sleep.h>
#include <linux/suspend.h>

#include "pci-host-common.h"

static int link_up_timeout = 500;
module_param(link_up_timeout, int, 0644);
MODULE_PARM_DESC(link_up_timeout, "PCIe link training timeout in milliseconds");

/*
 * System sleep (native5 = aurora + Tanabota, by function). Asahi's driver has
 * no PM of its own, and a daily boot keeps it that way: every path below is
 * behind a switch that is read-only after boot and off by default.
 */
static bool s2idle_hold_domains;
module_param(s2idle_hold_domains, bool, 0444);
MODULE_PARM_DESC(s2idle_hold_domains, "Hold the host's power domains on through suspend-to-idle (aurora's internal-link hold)");

/*
 * The t6020 bench's sleep (native5, Tanabota notes 68-79): macOS 13's own
 * teardown of the internal ports and root complex, and its way back.
 */
static uint bench_perst;
module_param(bench_perst, uint, 0444);
MODULE_PARM_DESC(bench_perst, "bench: at suspend_noirq, 3 (t602x): macOS 13's own, endpoints to D3hot, each port's disableGated/disablePortHardware, then _disableRootComplex (shared PHY, axi2af); 4 (t602x): 3, with the ADT dart-tunables-instance-0 applied to both internal PCIe DARTs first (Tanabota note 69)");

/* Tanabota note 68: macOS writes gP16 (port01's pwren) in its device round; which ports drop it */
static uint bench_pwren_off;
module_param(bench_pwren_off, uint, 0444);
MODULE_PARM_DESC(bench_pwren_off, "bench: with bench_perst=3/4, mask of the internal ports whose pwren goes low after PERST# (bit 1: port01, as macOS's gP16 write)");

static uint bench_gpfix;
module_param(bench_gpfix, uint, 0444);
MODULE_PARM_DESC(bench_gpfix, "bench: with bench_perst=3/4 (t602x), what macOS 13 does in the APCIE_GP domain that Linux doesn't (Tanabota note 75): 1 poll each lane refclk ack low after its request is cleared and re-read both lanes before the root complex goes down (diagnostic), 2 port 1 first, as macOS, 4 each port's IRQ mask <- 0x7f5527ff and status <- 0xf0 first and its status acked last, as macOS, 8 port +0x4020 <- 7 (the port's second page) before PME_Turn_Off, as macOS's runtime writes and aurora's M5 sleep data");

static bool bench_resume;
module_param(bench_resume, bool, 0444);
MODULE_PARM_DESC(bench_resume, "bench: with bench_perst=3/4 (t602x), at resume_noirq bring back what its entry took down: the root complex in the reverse order of _disableRootComplex, then each port's refclk, PERST#, RID2SID, MSI doorbell (apple_sleep.hybrid bit 13), IRQ mask and link, and the internal DARTs held (host_resumes) until then (Tanabota notes 77 §14.8, 78 §3.1)");

/* T8103 (original M1) and related SoCs */
#define CORE_RC_PHYIF_CTL		0x00024
#define   CORE_RC_PHYIF_CTL_RUN		BIT(0)
#define CORE_RC_PHYIF_STAT		0x00028
#define   CORE_RC_PHYIF_STAT_REFCLK	BIT(4)
#define CORE_RC_CTL			0x00050
#define   CORE_RC_CTL_RUN		BIT(0)
#define CORE_RC_STAT			0x00058
#define   CORE_RC_STAT_READY		BIT(0)
#define CORE_FABRIC_STAT		0x04000
#define   CORE_FABRIC_STAT_MASK		0x001F001F

#define CORE_PHY_DEFAULT_BASE(port)	(0x84000 + 0x4000 * (port))

#define PHY_LANE_CFG			0x00000
#define   PHY_LANE_CFG_REFCLK0REQ	BIT(0)
#define   PHY_LANE_CFG_REFCLK1REQ	BIT(1)
#define   PHY_LANE_CFG_REFCLK0ACK	BIT(2)
#define   PHY_LANE_CFG_REFCLK1ACK	BIT(3)
#define   PHY_LANE_CFG_REFCLKEN		(BIT(9) | BIT(10))
#define   PHY_LANE_CFG_REFCLKCGEN	(BIT(30) | BIT(31))
#define PHY_LANE_CTL			0x00004
#define   PHY_LANE_CTL_CFGACC		BIT(15)

#define PORT_LTSSMCTL			0x00080
#define   PORT_LTSSMCTL_START		BIT(0)
/* T6050: a trace of macOS shows 0x11 written here to send PME_Turn_Off */
#define PORT_PME_TURN_OFF		0x00088
/* Reads back 0 within a few reads of the write (the trace reads 0x1, then 0x10) */
#define   PORT_PME_TURN_OFF_SEND	BIT(0)
/* Written with bit 0 and still set afterwards; meaning not known */
#define   PORT_PME_TURN_OFF_BIT4	BIT(4)
#define PORT_INTSTAT			0x00100
#define   PORT_INT_TUNNEL_ERR		31
#define   PORT_INT_CPL_TIMEOUT		23
#define   PORT_INT_RID2SID_MAPERR	22
#define   PORT_INT_CPL_ABORT		21
#define   PORT_INT_MSI_BAD_DATA		19
#define   PORT_INT_MSI_ERR		18
#define   PORT_INT_REQADDR_GT32		17
#define   PORT_INT_AF_TIMEOUT		15
#define   PORT_INT_LINK_DOWN		14
#define   PORT_INT_LINK_UP		12
#define   PORT_INT_LINK_BWMGMT		11
#define   PORT_INT_AER_MASK		(15 << 4)
#define   PORT_INT_PORT_ERR		4
#define   PORT_INT_INTx(i)		i
#define   PORT_INT_INTx_MASK		15
#define PORT_INTMSK			0x00104
#define PORT_INTMSKSET			0x00108
#define PORT_INTMSKCLR			0x0010c
#define PORT_MSICFG			0x00124
#define   PORT_MSICFG_EN		BIT(0)
#define   PORT_MSICFG_L2MSINUM_SHIFT	4
#define PORT_MSIBASE			0x00128
#define   PORT_MSIBASE_1_SHIFT		16
#define PORT_MSIADDR			0x00168
#define PORT_LINKSTS			0x00208
#define   PORT_LINKSTS_UP		BIT(0)
#define   PORT_LINKSTS_BUSY		BIT(2)
#define   PORT_LINKSTS_L2		BIT(6)
#define PORT_LINKCMDSTS			0x00210
#define PORT_OUTS_NPREQS		0x00284
#define   PORT_OUTS_NPREQS_REQ		BIT(24)
#define   PORT_OUTS_NPREQS_CPL		BIT(16)
#define PORT_RXWR_FIFO			0x00288
#define   PORT_RXWR_FIFO_HDR		GENMASK(15, 10)
#define   PORT_RXWR_FIFO_DATA		GENMASK(9, 0)
#define PORT_RXRD_FIFO			0x0028C
#define   PORT_RXRD_FIFO_REQ		GENMASK(6, 0)
#define PORT_OUTS_CPLS			0x00290
#define   PORT_OUTS_CPLS_SHRD		GENMASK(14, 8)
#define   PORT_OUTS_CPLS_WAIT		GENMASK(6, 0)
#define PORT_APPCLK			0x00800
#define   PORT_APPCLK_EN		BIT(0)
#define   PORT_APPCLK_CGDIS		BIT(8)
#define PORT_STATUS			0x00804
#define   PORT_STATUS_READY		BIT(0)
#define PORT_REFCLK			0x00810
#define   PORT_REFCLK_EN		BIT(0)
#define   PORT_REFCLK_CGDIS		BIT(8)
#define PORT_PERST			0x00814
#define   PORT_PERST_OFF		BIT(0)
#define PORT_RID2SID			0x00828
#define   PORT_RID2SID_VALID		BIT(31)
#define   PORT_RID2SID_SID_SHIFT	16
#define   PORT_RID2SID_BUS_SHIFT	8
#define   PORT_RID2SID_DEV_SHIFT	3
#define   PORT_RID2SID_FUNC_SHIFT	0
#define PORT_OUTS_PREQS_HDR		0x00980
#define   PORT_OUTS_PREQS_HDR_MASK	GENMASK(9, 0)
#define PORT_OUTS_PREQS_DATA		0x00984
#define   PORT_OUTS_PREQS_DATA_MASK	GENMASK(15, 0)
#define PORT_TUNCTRL			0x00988
#define   PORT_TUNCTRL_PERST_ON		BIT(0)
#define   PORT_TUNCTRL_PERST_ACK_REQ	BIT(1)
#define PORT_TUNSTAT			0x0098c
#define   PORT_TUNSTAT_PERST_ON		BIT(0)
#define   PORT_TUNSTAT_PERST_ACK_PEND	BIT(1)
#define PORT_PREFMEM_ENABLE		0x00994

/* T602x (M2-pro and co) */
#define PORT_T602X_MSIADDR	0x016c
#define PORT_T602X_MSIADDR_HI	0x0170
#define PORT_T602X_PERST	0x082c
#define PORT_T602X_RID2SID	0x3000
#define PORT_T602X_MSIMAP	0x3800

#define PORT_MSIMAP_ENABLE	BIT(31)
#define PORT_MSIMAP_TARGET	GENMASK(7, 0)

/*
 * The doorbell address is set to 0xfffff000, which by convention
 * matches what MacOS does, and it is possible to use any other
 * address (in the bottom 4GB, as the base register is only 32bit).
 * However, it has to be excluded from the IOVA range, and the DART
 * driver has to know about it.
 */
#define DOORBELL_ADDR		CONFIG_PCIE_APPLE_MSI_DOORBELL_ADDR

struct hw_info {
	u32 phy_lane_ctl;
	u32 port_msiaddr;
	u32 port_msiaddr_hi;
	u32 port_refclk;
	u32 port_perst;
	u32 port_rid2sid;
	u32 port_msimap;
	u32 max_rid2sid;
};

static const struct hw_info t8103_hw = {
	.phy_lane_ctl		= PHY_LANE_CTL,
	.port_msiaddr		= PORT_MSIADDR,
	.port_msiaddr_hi	= 0,
	.port_refclk		= PORT_REFCLK,
	.port_perst		= PORT_PERST,
	.port_rid2sid		= PORT_RID2SID,
	.port_msimap		= 0,
	.max_rid2sid		= 64,
};

static const struct hw_info t602x_hw = {
	.phy_lane_ctl		= 0,
	.port_msiaddr		= PORT_T602X_MSIADDR,
	.port_msiaddr_hi	= PORT_T602X_MSIADDR_HI,
	.port_refclk		= 0,
	.port_perst		= PORT_T602X_PERST,
	.port_rid2sid		= PORT_T602X_RID2SID,
	.port_msimap		= PORT_T602X_MSIMAP,
	/* 16 on t602x, guess for autodetect on future HW */
	.max_rid2sid		= 512,
};

struct apple_pcie_pd {
	struct device		*dev;
	struct notifier_block	nb;
	unsigned int		vetoed;
};

struct apple_pcie {
	struct mutex		lock;
	struct device		*dev;
	void __iomem            *base;
	struct pci_config_window *cfg;
	struct apple_pcie_pd	*pds;
	unsigned int		num_pds;
	unsigned int		pd_held;
	/* bench_perst=3/4 took the t602x root complex and ports down at the last suspend_noirq. */
	bool			bench_rc_off;
	const struct hw_info	*hw;
	unsigned long		*bitmap;
	struct list_head	ports;
	struct completion	event;
	struct irq_fwspec	fwspec;
	u32			nvecs;
};

struct apple_pcie_port {
	raw_spinlock_t		lock;
	raw_spinlock_t		irq_lock;
	struct apple_pcie	*pcie;
	struct device_node	*np;
	void __iomem		*base;
	void __iomem		*phy;
	struct irq_domain	*domain;
	struct list_head	entry;
	unsigned long		*sid_map;
	u32			*saved_rid2sid;
	u32			saved_intmask;
	int			sid_map_sz;
	unsigned int		irq;
	bool			irq_disabled;
	/* PERST# and pwren of a port with a single reset line that Linux trained (bench resume). */
	struct gpio_desc	*perst_gpio;
	struct gpio_desc	*pwren_gpio;
	int			idx;
};

static void rmw_set(u32 set, void __iomem *addr)
{
	writel_relaxed(readl_relaxed(addr) | set, addr);
}

static void rmw_clear(u32 clr, void __iomem *addr)
{
	writel_relaxed(readl_relaxed(addr) & ~clr, addr);
}

static void apple_msi_compose_msg(struct irq_data *data, struct msi_msg *msg)
{
	msg->address_hi = upper_32_bits(DOORBELL_ADDR);
	msg->address_lo = lower_32_bits(DOORBELL_ADDR);
	msg->data = data->hwirq;
}

static struct irq_chip apple_msi_bottom_chip = {
	.name			= "MSI",
	.irq_mask		= irq_chip_mask_parent,
	.irq_unmask		= irq_chip_unmask_parent,
	.irq_eoi		= irq_chip_eoi_parent,
	.irq_set_affinity	= irq_chip_set_affinity_parent,
	.irq_set_type		= irq_chip_set_type_parent,
	.irq_compose_msi_msg	= apple_msi_compose_msg,
};

static int apple_msi_domain_alloc(struct irq_domain *domain, unsigned int virq,
				  unsigned int nr_irqs, void *args)
{
	struct apple_pcie *pcie = domain->host_data;
	struct irq_fwspec fwspec = pcie->fwspec;
	unsigned int i;
	int ret, hwirq;

	mutex_lock(&pcie->lock);

	hwirq = bitmap_find_free_region(pcie->bitmap, pcie->nvecs,
					order_base_2(nr_irqs));

	mutex_unlock(&pcie->lock);

	if (hwirq < 0)
		return -ENOSPC;

	fwspec.param[fwspec.param_count - 2] += hwirq;

	ret = irq_domain_alloc_irqs_parent(domain, virq, nr_irqs, &fwspec);
	if (ret)
		return ret;

	for (i = 0; i < nr_irqs; i++) {
		irq_domain_set_hwirq_and_chip(domain, virq + i, hwirq + i,
					      &apple_msi_bottom_chip, pcie);
	}

	return 0;
}

static void apple_msi_domain_free(struct irq_domain *domain, unsigned int virq,
				  unsigned int nr_irqs)
{
	struct irq_data *d = irq_domain_get_irq_data(domain, virq);
	struct apple_pcie *pcie = domain->host_data;

	mutex_lock(&pcie->lock);

	bitmap_release_region(pcie->bitmap, d->hwirq, order_base_2(nr_irqs));

	mutex_unlock(&pcie->lock);
}

static const struct irq_domain_ops apple_msi_domain_ops = {
	.alloc	= apple_msi_domain_alloc,
	.free	= apple_msi_domain_free,
};

static void apple_port_irq_mask(struct irq_data *data)
{
	struct apple_pcie_port *port = irq_data_get_irq_chip_data(data);

	guard(raw_spinlock_irqsave)(&port->lock);
	rmw_set(BIT(data->hwirq), port->base + PORT_INTMSK);
}

static void apple_port_irq_unmask(struct irq_data *data)
{
	struct apple_pcie_port *port = irq_data_get_irq_chip_data(data);

	guard(raw_spinlock_irqsave)(&port->lock);
	rmw_clear(BIT(data->hwirq), port->base + PORT_INTMSK);
}

static bool hwirq_is_intx(unsigned int hwirq)
{
	return BIT(hwirq) & PORT_INT_INTx_MASK;
}

static void apple_port_irq_ack(struct irq_data *data)
{
	struct apple_pcie_port *port = irq_data_get_irq_chip_data(data);

	if (!hwirq_is_intx(data->hwirq))
		writel_relaxed(BIT(data->hwirq), port->base + PORT_INTSTAT);
}

static int apple_port_irq_set_type(struct irq_data *data, unsigned int type)
{
	/*
	 * It doesn't seem that there is any way to configure the
	 * trigger, so assume INTx have to be level (as per the spec),
	 * and the rest is edge (which looks likely).
	 */
	if (hwirq_is_intx(data->hwirq) ^ !!(type & IRQ_TYPE_LEVEL_MASK))
		return -EINVAL;

	irqd_set_trigger_type(data, type);
	return 0;
}

static struct irq_chip apple_port_irqchip = {
	.name		= "PCIe",
	.irq_ack	= apple_port_irq_ack,
	.irq_mask	= apple_port_irq_mask,
	.irq_unmask	= apple_port_irq_unmask,
	.irq_set_type	= apple_port_irq_set_type,
};

static int apple_port_irq_domain_alloc(struct irq_domain *domain,
				       unsigned int virq, unsigned int nr_irqs,
				       void *args)
{
	struct apple_pcie_port *port = domain->host_data;
	struct irq_fwspec *fwspec = args;
	int i;

	for (i = 0; i < nr_irqs; i++) {
		irq_flow_handler_t flow = handle_edge_irq;
		unsigned int type = IRQ_TYPE_EDGE_RISING;

		if (hwirq_is_intx(fwspec->param[0] + i)) {
			flow = handle_level_irq;
			type = IRQ_TYPE_LEVEL_HIGH;
		}

		irq_domain_set_info(domain, virq + i, fwspec->param[0] + i,
				    &apple_port_irqchip, port, flow,
				    NULL, NULL);

		irq_set_irq_type(virq + i, type);
	}

	return 0;
}

static void apple_port_irq_domain_free(struct irq_domain *domain,
				       unsigned int virq, unsigned int nr_irqs)
{
	int i;

	for (i = 0; i < nr_irqs; i++) {
		struct irq_data *d = irq_domain_get_irq_data(domain, virq + i);

		irq_set_handler(virq + i, NULL);
		irq_domain_reset_irq_data(d);
	}
}

static const struct irq_domain_ops apple_port_irq_domain_ops = {
	.translate	= irq_domain_translate_onecell,
	.alloc		= apple_port_irq_domain_alloc,
	.free		= apple_port_irq_domain_free,
};

static void apple_port_irq_handler(struct irq_desc *desc)
{
	struct apple_pcie_port *port = irq_desc_get_handler_data(desc);
	struct irq_chip *chip = irq_desc_get_chip(desc);
	unsigned long stat;
	int i;

	chained_irq_enter(chip, desc);

	raw_spin_lock(&port->irq_lock);
	if (port->irq_disabled)
		goto out;

	stat = readl_relaxed(port->base + PORT_INTSTAT);

	for_each_set_bit(i, &stat, 32)
		generic_handle_domain_irq(port->domain, i);

out:
	raw_spin_unlock(&port->irq_lock);
	chained_irq_exit(chip, desc);
}

static int apple_pcie_port_setup_irq(struct apple_pcie_port *port)
{
	struct fwnode_handle *fwnode = &port->np->fwnode;
	struct apple_pcie *pcie = port->pcie;
	unsigned int irq;
	u32 val = 0;

	/* FIXME: consider moving each interrupt under each port */
	irq = irq_of_parse_and_map(to_of_node(dev_fwnode(port->pcie->dev)),
				   port->idx);
	if (!irq)
		return -ENXIO;
	port->irq = irq;

	port->domain = irq_domain_create_linear(fwnode, 32,
						&apple_port_irq_domain_ops,
						port);
	if (!port->domain)
		return -ENOMEM;

	/* Disable all interrupts */
	writel_relaxed(~0, port->base + PORT_INTMSK);
	writel_relaxed(~0, port->base + PORT_INTSTAT);
	writel_relaxed(~0, port->base + PORT_LINKCMDSTS);

	irq_set_chained_handler_and_data(irq, apple_port_irq_handler, port);

	/* Configure MSI base address */
	BUILD_BUG_ON(upper_32_bits(DOORBELL_ADDR));
	writel_relaxed(lower_32_bits(DOORBELL_ADDR),
		       port->base + pcie->hw->port_msiaddr);
	if (pcie->hw->port_msiaddr_hi)
		writel_relaxed(0, port->base + pcie->hw->port_msiaddr_hi);

	/* Enable MSIs, shared between all ports */
	if (pcie->hw->port_msimap) {
		for (int i = 0; i < pcie->nvecs; i++)
			writel_relaxed(FIELD_PREP(PORT_MSIMAP_TARGET, i) |
				       PORT_MSIMAP_ENABLE,
				       port->base + pcie->hw->port_msimap + 4 * i);
	} else {
		writel_relaxed(0, port->base + PORT_MSIBASE);
		val = ilog2(pcie->nvecs) << PORT_MSICFG_L2MSINUM_SHIFT;
	}

	writel_relaxed(val | PORT_MSICFG_EN, port->base + PORT_MSICFG);
	return 0;
}

static irqreturn_t apple_pcie_port_irq(int irq, void *data)
{
	struct apple_pcie_port *port = data;
	unsigned int hwirq = irq_domain_get_irq_data(port->domain, irq)->hwirq;

	switch (hwirq) {
	case PORT_INT_LINK_UP:
		dev_info_ratelimited(port->pcie->dev, "Link up on %pOF\n",
				     port->np);
		complete_all(&port->pcie->event);
		break;
	case PORT_INT_LINK_DOWN:
		dev_info_ratelimited(port->pcie->dev, "Link down on %pOF\n",
				     port->np);
		break;
	default:
		return IRQ_NONE;
	}

	return IRQ_HANDLED;
}

static int apple_pcie_port_register_irqs(struct apple_pcie_port *port)
{
	static struct {
		unsigned int	hwirq;
		const char	*name;
	} port_irqs[] = {
		{ PORT_INT_LINK_UP,	"Link up",	},
		{ PORT_INT_LINK_DOWN,	"Link down",	},
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(port_irqs); i++) {
		struct irq_fwspec fwspec = {
			.fwnode		= &port->np->fwnode,
			.param_count	= 1,
			.param		= {
				[0]	= port_irqs[i].hwirq,
			},
		};
		unsigned int irq;
		int ret;

		irq = irq_domain_alloc_irqs(port->domain, 1, NUMA_NO_NODE,
					    &fwspec);
		if (WARN_ON(!irq))
			continue;

		ret = request_irq(irq, apple_pcie_port_irq, 0,
				  port_irqs[i].name, port);
		WARN_ON(ret);
	}

	return 0;
}

static int apple_pcie_setup_refclk(struct apple_pcie *pcie,
				   struct apple_pcie_port *port)
{
	u32 stat;
	int res;

	if (pcie->hw->phy_lane_ctl)
		rmw_set(PHY_LANE_CTL_CFGACC, port->phy + pcie->hw->phy_lane_ctl);

	rmw_set(PHY_LANE_CFG_REFCLK0REQ, port->phy + PHY_LANE_CFG);

	res = readl_relaxed_poll_timeout(port->phy + PHY_LANE_CFG,
					 stat, stat & PHY_LANE_CFG_REFCLK0ACK,
					 100, 50000);
	if (res < 0)
		return res;

	rmw_set(PHY_LANE_CFG_REFCLK1REQ, port->phy + PHY_LANE_CFG);
	res = readl_relaxed_poll_timeout(port->phy + PHY_LANE_CFG,
					 stat, stat & PHY_LANE_CFG_REFCLK1ACK,
					 100, 50000);

	if (res < 0)
		return res;

	if (pcie->hw->phy_lane_ctl)
		rmw_clear(PHY_LANE_CTL_CFGACC, port->phy + pcie->hw->phy_lane_ctl);

	rmw_set(PHY_LANE_CFG_REFCLKEN, port->phy + PHY_LANE_CFG);

	if (pcie->hw->port_refclk)
		rmw_set(PORT_REFCLK_EN, port->base + pcie->hw->port_refclk);

	return 0;
}

static void __iomem *port_rid2sid_addr(struct apple_pcie_port *port, int idx)
{
	return port->base + port->pcie->hw->port_rid2sid + 4 * idx;
}

static u32 apple_pcie_rid2sid_write(struct apple_pcie_port *port,
				    int idx, u32 val)
{
	writel_relaxed(val, port_rid2sid_addr(port, idx));
	/* Read back to ensure completion of the write */
	return readl_relaxed(port_rid2sid_addr(port, idx));
}

static u32 port_rid2sid_offset(struct apple_pcie_port *port, int idx)
{
	return port->pcie->hw->port_rid2sid + 4 * idx;
}

static inline void apple_pcie_port_writel(struct apple_pcie_port *port, u32 value, u32 offset)
{
	writel_relaxed(value, port->base + offset);
}

static inline u32 apple_pcie_port_readl(struct apple_pcie_port *port, u32 offset)
{
	return readl_relaxed(port->base + offset);
}

static void apple_pcie_port_rmw_set(struct apple_pcie_port *port, u32 set, u32 offset)
{
	apple_pcie_port_writel(port, apple_pcie_port_readl(port, offset) | set, offset);
}

static void apple_pcie_port_rmw_clear(struct apple_pcie_port *port, u32 clear, u32 offset)
{
	apple_pcie_port_writel(port, apple_pcie_port_readl(port, offset) & ~clear, offset);
}

/*
 * The sleep path's gate on the port's chained IRQ (aurora, native5): neither
 * disable_irq() nor synchronize_irq() waits for a chained handler that is
 * already running. Closing the gate under irq_lock does, and any later handler
 * skips the port registers. AIC has no irq_disable callback, so a lazy disable
 * would only mark the parent disabled: the line is made unlazy first. Only the
 * sleep paths call these.
 */
static void apple_pcie_port_disable_irq(struct apple_pcie_port *port)
{
	unsigned long flags;

	if (!port->irq || !port->domain || port->irq_disabled)
		return;

	irq_set_status_flags(port->irq, IRQ_DISABLE_UNLAZY);
	disable_irq_nosync(port->irq);
	raw_spin_lock_irqsave(&port->irq_lock, flags);
	port->irq_disabled = true;
	raw_spin_unlock_irqrestore(&port->irq_lock, flags);
}

static void apple_pcie_port_enable_irq(struct apple_pcie_port *port)
{
	unsigned long flags;

	if (!port->irq_disabled)
		return;

	raw_spin_lock_irqsave(&port->irq_lock, flags);
	port->irq_disabled = false;
	raw_spin_unlock_irqrestore(&port->irq_lock, flags);
	enable_irq(port->irq);
}

static int apple_pcie_setup_link(struct apple_pcie *pcie,
				 struct apple_pcie_port *port,
				 struct device_node *np)
{
#define MAX_AUX_PERST 3
	struct gpio_desc *aux_reset[MAX_AUX_PERST] = { NULL };
	u32 num_aux_resets = 0;
	struct gpio_desc *reset, *pwren = NULL;
	u32 stat;
	int ret;

	/*
	 * Assert PERST# and configure the pin as output.
	 * The Aquantia AQC113 10GB nic used desktop macs is sensitive to
	 * deasserting it without prior clock setup.
	 * Observed on M1 Max/Ultra Mac Studios under m1n1's hypervisor.
	 */
	reset = devm_fwnode_gpiod_get(pcie->dev, of_fwnode_handle(np), "reset",
				      GPIOD_OUT_HIGH, "PERST#");
	if (IS_ERR(reset))
		return PTR_ERR(reset);
	// HACK: use additional "reset-gpios" until pci-pwrctrl gains PERST# support.
	for (u32 idx = 0; idx < MAX_AUX_PERST; idx++) {
		aux_reset[idx] = devm_fwnode_gpiod_get_index(pcie->dev,
							     of_fwnode_handle(np),
							     "reset", idx + 1,
							     GPIOD_OUT_HIGH,
							     "PERST#");
		if (IS_ERR(aux_reset[idx])) {
			if (PTR_ERR(aux_reset[idx]) == -ENOENT)
				break;
			else
				return PTR_ERR(aux_reset[idx]);
		}
		num_aux_resets++;
	}
	dev_info(pcie->dev, "Using %u auxiliary PERST#\n", num_aux_resets);

	pwren = devm_fwnode_gpiod_get(pcie->dev, of_fwnode_handle(np), "pwren",
					    GPIOD_ASIS, "PWREN");
	if (IS_ERR(pwren)) {
		if (PTR_ERR(pwren) == -ENOENT)
			pwren = NULL;
		else
			return PTR_ERR(pwren);
	}
	/* Kept for the bench's resume, which takes them through the same steps. */
	if (!num_aux_resets) {
		port->perst_gpio = reset;
		port->pwren_gpio = pwren;
	}

	rmw_set(PORT_APPCLK_EN, port->base + PORT_APPCLK);

	/* Assert PERST# before setting up the clock */
	gpiod_set_value_cansleep(reset, 1);
	for (u32 idx = 0; idx < num_aux_resets; idx++)
		gpiod_set_value_cansleep(aux_reset[idx], 1);

	/* Power on the device if required */
	gpiod_set_value_cansleep(pwren, 1);

	ret = apple_pcie_setup_refclk(pcie, port);
	if (ret < 0)
		return ret;

	/*
	 * The minimal Tperst-clk value is 100us (PCIe CEM r5.0, 2.9.2)
	 * If powering up, the minimal Tpvperl is 100ms
	 */
	if (pwren)
		msleep(100);
	else
		usleep_range(100, 200);

	/* Deassert PERST# */
	rmw_set(PORT_PERST_OFF, port->base + pcie->hw->port_perst);
	gpiod_set_value_cansleep(reset, 0);
	for (u32 idx = 0; idx < num_aux_resets; idx++)
		gpiod_set_value_cansleep(aux_reset[idx], 0);

	/* Wait for 100ms after PERST# deassertion (PCIe r5.0, 6.6.1) */
	msleep(100);

	ret = readl_relaxed_poll_timeout(port->base + PORT_STATUS, stat,
					 stat & PORT_STATUS_READY, 100, 250000);
	if (ret < 0) {
		dev_err(pcie->dev, "port %pOF ready wait timeout\n", np);
		return ret;
	}

	return 0;
}

static int apple_pcie_setup_port(struct apple_pcie *pcie,
				 struct device_node *np)
{
	struct platform_device *platform = to_platform_device(pcie->dev);
	struct apple_pcie_port *port;
	struct resource *res;
	char name[16];
	u32 link_stat, idx;
	int ret, i;

	port = devm_kzalloc(pcie->dev, sizeof(*port), GFP_KERNEL);
	if (!port)
		return -ENOMEM;

	port->sid_map = devm_bitmap_zalloc(pcie->dev, pcie->hw->max_rid2sid, GFP_KERNEL);
	if (!port->sid_map)
		return -ENOMEM;

	/* What a sleep that takes the port down puts back at resume. */
	port->saved_rid2sid = devm_kcalloc(pcie->dev, pcie->hw->max_rid2sid,
					   sizeof(*port->saved_rid2sid), GFP_KERNEL);
	if (!port->saved_rid2sid)
		return -ENOMEM;

	ret = of_property_read_u32_index(np, "reg", 0, &idx);
	if (ret)
		return ret;

	/* Use the first reg entry to work out the port index */
	port->idx = idx >> 11;
	port->pcie = pcie;
	port->np = np;

	raw_spin_lock_init(&port->lock);
	raw_spin_lock_init(&port->irq_lock);

	snprintf(name, sizeof(name), "port%d", port->idx);
	res = platform_get_resource_byname(platform, IORESOURCE_MEM, name);
	if (!res)
		res = platform_get_resource(platform, IORESOURCE_MEM, port->idx + 2);

	port->base = devm_ioremap_resource(&platform->dev, res);
	if (IS_ERR(port->base))
		return PTR_ERR(port->base);

	snprintf(name, sizeof(name), "phy%d", port->idx);
	res = platform_get_resource_byname(platform, IORESOURCE_MEM, name);
	if (res)
		port->phy = devm_ioremap_resource(&platform->dev, res);
	else
		port->phy = pcie->base + CORE_PHY_DEFAULT_BASE(port->idx);

	/* link might be already brought up by u-boot, skip setup then */
	link_stat = readl_relaxed(port->base + PORT_LINKSTS);
	if (!(link_stat & PORT_LINKSTS_UP)) {
		ret = apple_pcie_setup_link(pcie, port, np);
		if (ret)
			return ret;
	}

	if (pcie->hw->port_refclk)
		rmw_clear(PORT_REFCLK_CGDIS, port->base + pcie->hw->port_refclk);
	else
		rmw_set(PHY_LANE_CFG_REFCLKCGEN, port->phy + PHY_LANE_CFG);

	rmw_clear(PORT_APPCLK_CGDIS, port->base + PORT_APPCLK);

	ret = apple_pcie_port_setup_irq(port);
	if (ret)
		return ret;

	/* Reset all RID/SID mappings, and check for RAZ/WI registers */
	for (i = 0; i < pcie->hw->max_rid2sid; i++) {
		if (apple_pcie_rid2sid_write(port, i, 0xbad1d) != 0xbad1d)
			break;
		apple_pcie_rid2sid_write(port, i, 0);
	}

	dev_dbg(pcie->dev, "%pOF: %d RID/SID mapping entries\n", np, i);

	port->sid_map_sz = i;

	list_add_tail(&port->entry, &pcie->ports);
	init_completion(&pcie->event);

	/* In the success path, we keep a reference to np around */
	of_node_get(np);

	ret = apple_pcie_port_register_irqs(port);
	WARN_ON(ret);

	link_stat = readl_relaxed(port->base + PORT_LINKSTS);
	if (!(link_stat & PORT_LINKSTS_UP)) {
		unsigned long timeout, left;
		/* start link training */
		writel_relaxed(PORT_LTSSMCTL_START, port->base + PORT_LTSSMCTL);

		timeout = link_up_timeout * HZ / 1000;
		left = wait_for_completion_timeout(&pcie->event, timeout);
		if (!left)
			dev_warn(pcie->dev, "%pOF link didn't come up\n", np);
		else
			dev_info(pcie->dev, "%pOF link up after %ldms\n", np,
				 (timeout - left) * 1000 / HZ);

	}

	return 0;
}

static const struct msi_parent_ops apple_msi_parent_ops = {
	.supported_flags	= (MSI_GENERIC_FLAGS_MASK	|
				   MSI_FLAG_PCI_MSIX		|
				   MSI_FLAG_MULTI_PCI_MSI),
	.required_flags		= (MSI_FLAG_USE_DEF_DOM_OPS	|
				   MSI_FLAG_USE_DEF_CHIP_OPS	|
				   MSI_FLAG_PCI_MSI_MASK_PARENT),
	.chip_flags		= MSI_CHIP_FLAG_SET_EOI,
	.bus_select_token	= DOMAIN_BUS_PCI_MSI,
	.init_dev_msi_info	= msi_lib_init_dev_msi_info,
};

static int apple_msi_init(struct apple_pcie *pcie)
{
	struct fwnode_handle *fwnode = dev_fwnode(pcie->dev);
	struct irq_domain_info info = {
		.fwnode		= fwnode,
		.ops		= &apple_msi_domain_ops,
		.size		= pcie->nvecs,
		.host_data	= pcie,
	};
	struct of_phandle_args args = {};
	int ret;

	ret = of_parse_phandle_with_args(to_of_node(fwnode), "msi-ranges",
					 "#interrupt-cells", 0, &args);
	if (ret)
		return ret;

	ret = of_property_read_u32_index(to_of_node(fwnode), "msi-ranges",
					 args.args_count + 1, &pcie->nvecs);
	if (ret)
		return ret;

	of_phandle_args_to_fwspec(args.np, args.args, args.args_count,
				  &pcie->fwspec);

	pcie->bitmap = devm_bitmap_zalloc(pcie->dev, pcie->nvecs, GFP_KERNEL);
	if (!pcie->bitmap)
		return -ENOMEM;

	info.parent = irq_find_matching_fwspec(&pcie->fwspec, DOMAIN_BUS_WIRED);
	if (!info.parent) {
		dev_err(pcie->dev, "failed to find parent domain\n");
		return -ENXIO;
	}

	if (!msi_create_parent_irq_domain(&info, &apple_msi_parent_ops)) {
		dev_err(pcie->dev, "failed to create IRQ domain\n");
		return -ENOMEM;
	}
	return 0;
}

static struct apple_pcie *apple_pcie_lookup(struct device *dev)
{
	return pci_host_bridge_priv(dev_get_drvdata(dev));
}

static struct apple_pcie_port *apple_pcie_get_port(struct pci_dev *pdev)
{
	struct pci_config_window *cfg = pdev->sysdata;
	struct apple_pcie *pcie;
	struct pci_dev *port_pdev;
	struct apple_pcie_port *port;

	pcie = apple_pcie_lookup(cfg->parent);
	if (WARN_ON(!pcie))
		return NULL;

	/* Find the root port this device is on */
	port_pdev = pcie_find_root_port(pdev);

	/* If finding the port itself, nothing to do */
	if (WARN_ON(!port_pdev) || pdev == port_pdev)
		return NULL;

	list_for_each_entry(port, &pcie->ports, entry) {
		if (port->idx == PCI_SLOT(port_pdev->devfn))
			return port;
	}

	return NULL;
}

static int apple_pcie_enable_device(struct pci_host_bridge *bridge, struct pci_dev *pdev)
{
	u32 sid, rid = pci_dev_id(pdev);
	struct apple_pcie_port *port;
	struct of_phandle_args iommu_spec = {};
	int idx, err;

	port = apple_pcie_get_port(pdev);
	if (!port)
		return 0;

	dev_dbg(&pdev->dev, "added to bus %s, index %d\n",
		pci_name(pdev->bus->self), port->idx);

	err = of_map_iommu_id(port->pcie->dev->of_node, rid, &iommu_spec);
	if (err)
		return err;

	of_node_put(iommu_spec.np);
	sid = iommu_spec.args[0];
	mutex_lock(&port->pcie->lock);

	idx = bitmap_find_free_region(port->sid_map, port->sid_map_sz, 0);
	if (idx >= 0) {
		apple_pcie_rid2sid_write(port, idx,
					 PORT_RID2SID_VALID |
					 (sid << PORT_RID2SID_SID_SHIFT) | rid);

		dev_dbg(&pdev->dev, "mapping RID%x to SID%x (index %d)\n",
			rid, sid, idx);
	}

	mutex_unlock(&port->pcie->lock);

	return idx >= 0 ? 0 : -ENOSPC;
}

static void apple_pcie_disable_device(struct pci_host_bridge *bridge, struct pci_dev *pdev)
{
	struct apple_pcie_port *port;
	u32 rid = pci_dev_id(pdev);
	int idx;

	port = apple_pcie_get_port(pdev);
	if (!port)
		return;

	mutex_lock(&port->pcie->lock);

	for_each_set_bit(idx, port->sid_map, port->sid_map_sz) {
		u32 val;

		val = readl_relaxed(port_rid2sid_addr(port, idx));
		if ((val & 0xffff) == rid) {
			apple_pcie_rid2sid_write(port, idx, 0);
			bitmap_release_region(port->sid_map, idx, 0);
			dev_dbg(&pdev->dev, "Released %x (%d)\n", val, idx);
			break;
		}
	}

	mutex_unlock(&port->pcie->lock);
}

static int apple_pcie_init(struct pci_config_window *cfg)
{
	struct device *dev = cfg->parent;
	struct apple_pcie *pcie;
	int ret;

	pcie = apple_pcie_lookup(dev);
	if (WARN_ON(!pcie))
		return -ENOENT;
	pcie->cfg = cfg;

	for_each_available_child_of_node_scoped(dev->of_node, of_port) {
		ret = apple_pcie_setup_port(pcie, of_port);
		if (ret) {
			dev_err(dev, "Port %pOF setup fail: %d\n", of_port, ret);
			return ret;
		}
	}

	return 0;
}

static const struct pci_ecam_ops apple_pcie_cfg_ecam_ops = {
	.init		= apple_pcie_init,
	.enable_device	= apple_pcie_enable_device,
	.disable_device	= apple_pcie_disable_device,
	.pci_ops	= {
		.map_bus	= pci_ecam_map_bus,
		.read		= pci_generic_config_read,
		.write		= pci_generic_config_write,
	}
};

static int apple_pcie_probe_port(struct device_node *np)
{
	struct gpio_desc *gd;

	/* check whether the GPPIO pin exists but leave it as is */
	gd = fwnode_gpiod_get_index(of_fwnode_handle(np), "reset", 0,
				    GPIOD_ASIS, "PERST#");
	if (IS_ERR(gd))
		return PTR_ERR(gd);

	gpiod_put(gd);

	gd = fwnode_gpiod_get_index(of_fwnode_handle(np), "pwren", 0,
				    GPIOD_ASIS, "PWREN");
	if (IS_ERR(gd)) {
		if (PTR_ERR(gd) != -ENOENT)
			return PTR_ERR(gd);
	} else {
		gpiod_put(gd);
	}

	return 0;
}

/*
 * The host's power domains, for the suspend-to-idle hold (aurora): a single
 * domain is already attached by the platform bus; more are attached here.
 * Only with s2idle_hold_domains, so a daily boot attaches nothing new.
 */
static int apple_pcie_attach_domains(struct apple_pcie *pcie)
{
	struct device *dev = pcie->dev;
	struct dev_pm_domain_attach_data data = {
		.pd_flags = PD_FLAG_DEV_LINK_ON,
	};
	struct dev_pm_domain_list *list = NULL;
	int count, ret, i;

	if (!IS_ENABLED(CONFIG_PM) || !s2idle_hold_domains)
		return 0;
	if (!of_property_present(dev->of_node, "power-domains"))
		return 0;

	count = of_count_phandle_with_args(dev->of_node, "power-domains",
					   "#power-domain-cells");
	if (count < 0)
		return count;
	if (count > 1) {
		ret = devm_pm_domain_attach_list(dev, &data, &list);
		if (ret < 0)
			return ret;
		if (ret != count)
			return -ENODEV;
	} else if (!dev->pm_domain) {
		return 0;
	}

	pcie->pds = devm_kcalloc(dev, count, sizeof(*pcie->pds), GFP_KERNEL);
	if (!pcie->pds)
		return -ENOMEM;
	pcie->num_pds = count;
	for (i = 0; i < count; i++)
		pcie->pds[i].dev = list ? list->pd_devs[i] : dev;

	return 0;
}

static int apple_pcie_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pci_host_bridge *bridge;
	struct device_node *of_port;
	struct apple_pcie *pcie;
	int ret;

	/* Check for probe dependencies for all ports first */
	for_each_available_child_of_node(dev->of_node, of_port) {
		ret = apple_pcie_probe_port(of_port);
		if (ret) {
			of_node_put(of_port);
			return dev_err_probe(dev, ret, "Port %pOF probe fail\n", of_port);
		}
	}

	bridge = devm_pci_alloc_host_bridge(dev, sizeof(*pcie));
	if (!bridge)
		return -ENOMEM;

	pcie = pci_host_bridge_priv(bridge);
	pcie->dev = dev;
	pcie->hw = of_device_get_match_data(dev);
	if (!pcie->hw)
		return -ENODEV;
	pcie->base = devm_platform_ioremap_resource(pdev, 1);
	if (IS_ERR(pcie->base))
		return PTR_ERR(pcie->base);

	mutex_init(&pcie->lock);
	INIT_LIST_HEAD(&pcie->ports);

	ret = apple_msi_init(pcie);
	if (ret)
		return ret;

	ret = apple_pcie_attach_domains(pcie);
	if (ret)
		return dev_err_probe(dev, ret, "power domains not attached\n");

	return pci_host_common_init(pdev, bridge, &apple_pcie_cfg_ecam_ops);
}

/*
 * genpd powers a domain off for system sleep once every device in it is
 * through its noirq suspend. A host that keeps its links refuses that for the
 * sleep: the domain stays on, and its parents with it. IRQ-safe domains call
 * this in atomic context, so it only counts.
 */
static int apple_pcie_pd_notify(struct notifier_block *nb, unsigned long action, void *data)
{
	struct apple_pcie_pd *pd = container_of(nb, struct apple_pcie_pd, nb);

	if (action != GENPD_NOTIFY_PRE_OFF)
		return NOTIFY_OK;
	pd->vetoed++;
	return notifier_from_errno(-EBUSY);
}

static void apple_pcie_release_domains(struct apple_pcie *pcie)
{
	unsigned int vetoed = 0;
	struct apple_pcie_pd *pd;

	if (!pcie->pd_held)
		return;
	while (pcie->pd_held) {
		pd = &pcie->pds[--pcie->pd_held];
		dev_pm_genpd_remove_notifier(pd->dev);
		vetoed += pd->vetoed;
	}
	dev_dbg(pcie->dev, "PCIe power domains released after suspend-to-idle (%u power-offs refused)\n",
		vetoed);
}

/*
 * Hold every attached domain through a suspend-to-idle (aurora): internal
 * links are left running, and a domain cut under them loses the endpoints'
 * state with nothing here to retrain them. A domain already off has no link
 * to keep.
 */
static int apple_pcie_hold_domains(struct apple_pcie *pcie)
{
	struct apple_pcie_pd *pd;
	int ret;

	if (!pcie->num_pds)
		return -ENODEV;
	while (pcie->pd_held < pcie->num_pds) {
		pd = &pcie->pds[pcie->pd_held];
		pd->vetoed = 0;
		pd->nb.notifier_call = apple_pcie_pd_notify;
		ret = dev_pm_genpd_add_notifier(pd->dev, &pd->nb);
		if (ret)
			goto err_release;
		pcie->pd_held++;
		if (!dev_pm_genpd_is_on(pd->dev)) {
			ret = -ENODEV;
			goto err_release;
		}
	}
	return 0;

err_release:
	apple_pcie_release_domains(pcie);
	return ret;
}

/*
 * bench_perst=3, t602x: macOS 13.7.8's own sequence (Tanabota note 68). AppleT6020PCIe's
 * quiesce action runs each port's AppleEmbeddedPCIEPort::disableGated, then
 * AppleT6020PCIe::_disableRootComplex. By then macOS's endpoint drivers have powered their
 * IOPCIDevices off (D3hot); Linux binds none, so that is done here first. Unbounded polls of
 * macOS's are bounded, and every step's result is printed.
 */
#define T602X_BENCH_PHY_SHARED		0x0d008000	/* from rc: ADT apcie reg[4], 0x59e008000 */
#define T602X_BENCH_AXI2AF		0x0b000000	/* from rc: ADT apcie reg[6], 0x59c000000 */
#define   T602X_BENCH_AXI2AF_CTL	0x400
#define T602X_BENCH_PHY_CTRL_RESET	BIT(7)
#define RC_T602X_APPCLK_GATE_DIS	0x0003c
#define PORT_T602X_FIFO_STS		0x00820
#define PORT_T602X_CTL_13C		0x0013c
#define DWC_PORT_DEBUG0			0x728
#define   DWC_LTSSM_L1_IDLE		0x14
#define PHY_LANE_CFG_B14		BIT(14)

/*
 * bench_gpfix (Tanabota note 75): macOS 13's writes in the GP domain that bench_perst=3 doesn't
 * make, from its write log (pd782, pd783):
 * - bit 2: disableGated starts with port +0x104 <- 0x7f5527ff, +0x100 <- 0xf0 and ends, after
 *   rc +0x3c is cleared, with +0x100 <- the pending status (0x20006600 port 0, 0x30004200/0x30004300
 *   port 1). Linux only disables the IRQ line and leaves the status pending.
 * - bit 3: port 0 +0x4020 <- 7 three times a minute at runtime (last 3.5 s before slpw); aurora's
 *   M5 sleep data writes it at sleep. Linux's DT maps 0x4000 of the port, so it never does.
 * - bits 0/1: macOS's lane RMWs read both refclk acks low 4-7 us after REQ0 is cleared; every
 *   Linux bench_perst=3 run (16 of 16) leaves port 1 at 0xc00400c, acks high. macOS takes port 1
 *   down first (its SD driver, in the device round), Linux last.
 */
#define T602X_BENCH_GPFIX_LANEACK	BIT(0)
#define T602X_BENCH_GPFIX_ORDER		BIT(1)
#define T602X_BENCH_GPFIX_INT		BIT(2)
#define T602X_BENCH_GPFIX_4020		BIT(3)
#define T602X_BENCH_PORT_PAGE2(idx)	(0x0300c000 + (idx) * 0x01000000)	/* from rc */
#define T602X_BENCH_INTMSK_MACOS	0x7f5527ff
#define T602X_BENCH_INTSTAT_FIRST	0xf0

static int apple_pcie_bench_lane_clear(void __iomem *lane, u32 req, u32 ack)
{
	u32 v;

	writel(readl(lane) & ~req, lane);
	if (!(bench_gpfix & T602X_BENCH_GPFIX_LANEACK))
		return -ENODATA;
	return readl_poll_timeout_atomic(lane, v, !(v & ack), 1, 1000);
}

static void apple_pcie_bench_t602x_port_off(struct apple_pcie *pcie, struct apple_pcie_port *port,
					    struct pci_bus *bus)
{
	void __iomem *rp = pcie->cfg->win + (PCI_DEVFN(port->idx, 0) << 12);
	void __iomem *lane = port->phy + PHY_LANE_CFG;
	int nfn = 0, nd3 = 0, pme = -ENOLINK, l2 = -ENOLINK, fifo, ltssm, run, ack0, ack1;
	u32 v, lane0 = readl(lane), linksts, int0 = 0, int1 = 0, p4020 = 0, p4020n = 0;
	struct pci_dev *root, *fn;
	bool up, pwren_off;

	apple_pcie_port_disable_irq(port);
	if (bench_gpfix & T602X_BENCH_GPFIX_INT) {
		int0 = apple_pcie_port_readl(port, PORT_INTSTAT);
		apple_pcie_port_writel(port, T602X_BENCH_INTMSK_MACOS, PORT_INTMSK);
		apple_pcie_port_writel(port, T602X_BENCH_INTSTAT_FIRST, PORT_INTSTAT);
	}
	if (bench_gpfix & T602X_BENCH_GPFIX_4020) {
		struct resource *rc = platform_get_resource(to_platform_device(pcie->dev),
							    IORESOURCE_MEM, 1);
		void __iomem *p2 = rc ? ioremap_np(rc->start + T602X_BENCH_PORT_PAGE2(port->idx),
						   SZ_16K) : NULL;

		if (p2) {
			p4020 = readl(p2 + 0x20);
			writel(7, p2 + 0x20);
			p4020n = readl(p2 + 0x20);
			iounmap(p2);
		} else {
			dev_err(pcie->dev, "bench: port %d +0x4020 not mapped\n", port->idx);
		}
	}
	linksts = apple_pcie_port_readl(port, PORT_LINKSTS);
	up = linksts & PORT_LINKSTS_UP;

	/* The endpoints in D3hot: only from there do they take PME_Turn_Off into L2/L3 Ready */
	root = pci_get_slot(bus, PCI_DEVFN(port->idx, 0));
	if (root && root->subordinate && up) {
		list_for_each_entry(fn, &root->subordinate->devices, bus_list) {
			nfn++;
			if (!pci_set_power_state(fn, PCI_D3hot) && fn->current_state == PCI_D3hot)
				nd3++;
		}
	}
	/* disableGated: the root port's command off, its bus numbers cleared */
	if (root) {
		pci_write_config_word(root, PCI_COMMAND, 0);
		if (!pci_read_config_dword(root, PCI_PRIMARY_BUS, &v))
			pci_write_config_dword(root, PCI_PRIMARY_BUS, v & 0xff0000ff);
	}
	pci_dev_put(root);

	/* requestPMEToBroadcast (app clock auto-disable off, +0x88 <- 0x11), its ack, L2 */
	if (up) {
		apple_pcie_port_rmw_set(port, PORT_APPCLK_CGDIS, PORT_APPCLK);
		apple_pcie_port_writel(port, PORT_PME_TURN_OFF_SEND | PORT_PME_TURN_OFF_BIT4,
				       PORT_PME_TURN_OFF);
		pme = readl_poll_timeout(port->base + PORT_PME_TURN_OFF, v,
					 !(v & PORT_PME_TURN_OFF_SEND), 100, 10000);
		l2 = readl_poll_timeout(port->base + PORT_LINKSTS, v, v & PORT_LINKSTS_L2, 100, 50000);
	}
	/* setEndpointReset: PERST# through the ADT's function-perst (Linux's reset-gpios) */
	if (port->perst_gpio)
		gpiod_set_value_cansleep(port->perst_gpio, 1);
	/* enablePortRefclkGating(false) */
	writel(readl(lane) & ~PHY_LANE_CFG_REFCLKCGEN, lane);

	/* disablePortHardware */
	rmw_set(BIT(0), pcie->base + RC_T602X_APPCLK_GATE_DIS);
	fifo = readl_poll_timeout(port->base + PORT_T602X_FIFO_STS, v,
				  !(v & 0xff) || !(v & 0xff0000), 1, 1000);
	apple_pcie_port_rmw_set(port, BIT(8), PORT_T602X_CTL_13C);
	ltssm = readl_poll_timeout(rp + DWC_PORT_DEBUG0, v, (v & 0x3f) != DWC_LTSSM_L1_IDLE, 5, 5000);
	apple_pcie_port_rmw_clear(port, PORT_PERST_OFF, pcie->hw->port_perst);
	apple_pcie_port_rmw_clear(port, BIT(8), PORT_T602X_CTL_13C);
	writel(readl(lane) & ~PHY_LANE_CFG_REFCLKCGEN, lane);
	writel(readl(lane) & ~BIT(10), lane);
	writel(readl(lane) & ~BIT(9), lane);
	writel(readl(lane) | PHY_LANE_CFG_B14, lane);
	ack0 = apple_pcie_bench_lane_clear(lane, PHY_LANE_CFG_REFCLK0REQ, PHY_LANE_CFG_REFCLK0ACK);
	ack1 = apple_pcie_bench_lane_clear(lane, PHY_LANE_CFG_REFCLK1REQ, PHY_LANE_CFG_REFCLK1ACK);
	apple_pcie_port_rmw_clear(port, PORT_APPCLK_EN, PORT_APPCLK);
	run = readl_poll_timeout(port->base + PORT_STATUS, v, !(v & PORT_STATUS_READY), 1, 1000);
	rmw_clear(BIT(0), pcie->base + RC_T602X_APPCLK_GATE_DIS);
	if (bench_gpfix & T602X_BENCH_GPFIX_INT) {
		int1 = apple_pcie_port_readl(port, PORT_INTSTAT);
		apple_pcie_port_writel(port, int1, PORT_INTSTAT);
	}

	pwren_off = (bench_pwren_off & BIT(port->idx)) && port->pwren_gpio;
	if (pwren_off)
		gpiod_set_value_cansleep(port->pwren_gpio, 0);

	dev_info(pcie->dev,
		 "bench: port %d (linksts %#x) D3hot %d of %d, PME_Turn_Off %d, L2 %d (linksts %#x), PERST# asserted, fifo %d, ltssm %d (%#x), lane cfg %#x -> %#x, appclk off %d, pwren %s\n",
		 port->idx, linksts, nd3, nfn, pme, l2, apple_pcie_port_readl(port, PORT_LINKSTS),
		 fifo, ltssm, readl(rp + DWC_PORT_DEBUG0) & 0x3f, lane0, readl(lane), run,
		 pwren_off ? "low" : "kept");
	if (bench_gpfix)
		dev_info(pcie->dev,
			 "bench: gpfix %#x port %d: ack0 %d ack1 %d, intstat %#x first, %#x acked last (now %#x), +0x4020 %#x -> %#x\n",
			 bench_gpfix, port->idx, ack0, ack1, int0, int1,
			 (bench_gpfix & T602X_BENCH_GPFIX_INT) ?
			 apple_pcie_port_readl(port, PORT_INTSTAT) : 0, p4020, p4020n);
}

static void apple_pcie_bench_t602x_rc_off(struct apple_pcie *pcie)
{
	struct resource *rc = platform_get_resource(to_platform_device(pcie->dev), IORESOURCE_MEM, 1);
	void __iomem *phy, *axi;
	u32 v, phy0, axi0;
	int ack1, ack0;

	if (!rc)
		return;
	phy = ioremap_np(rc->start + T602X_BENCH_PHY_SHARED, SZ_16K);
	axi = ioremap_np(rc->start + T602X_BENCH_AXI2AF, SZ_16K);
	if (!phy || !axi) {
		dev_err(pcie->dev, "bench: shared PHY / axi2af not mapped\n");
		goto out;
	}
	phy0 = readl(phy);
	axi0 = readl(axi + T602X_BENCH_AXI2AF_CTL);

	/* _disableRootComplex, in order */
	udelay(10);
	writel(readl(phy) | T602X_BENCH_PHY_CTRL_RESET, phy);
	udelay(1);
	writel(readl(phy) & ~PHY_LANE_CFG_REFCLK1REQ, phy);
	ack1 = readl_poll_timeout(phy, v, !(v & PHY_LANE_CFG_REFCLK1ACK), 1, 10000);
	udelay(1);
	writel(readl(phy) & ~PHY_LANE_CFG_REFCLK0REQ, phy);
	ack0 = readl_poll_timeout(phy, v, !(v & PHY_LANE_CFG_REFCLK0ACK), 1, 10000);
	udelay(1);
	writel(readl(phy) & ~(BIT(9) | BIT(8)), phy);
	udelay(10);
	writel(readl(phy + 4) & ~BIT(4), phy + 4);
	writel(readl(phy + 4) & ~BIT(0), phy + 4);
	writel(readl(axi + T602X_BENCH_AXI2AF_CTL) & ~BIT(16), axi + T602X_BENCH_AXI2AF_CTL);

	dev_info(pcie->dev,
		 "bench: root complex off: shared PHY %#x -> %#x (ack1 %d, ack0 %d), +4 %#x, axi2af +0x400 %#x -> %#x\n",
		 phy0, readl(phy), ack1, ack0, readl(phy + 4), axi0,
		 readl(axi + T602X_BENCH_AXI2AF_CTL));
out:
	if (axi)
		iounmap(axi);
	if (phy)
		iounmap(phy);
}

/*
 * bench_perst=4, t602x (Tanabota note 69): the j416s ADT gives dart-apcie0/1 (0x594000000,
 * 0x595000000, both in APCIE_GP_SYS) a dart-tunables-instance-0 that macOS's AppleT8110DART
 * applies at setup. Nothing applies it under Linux: m1n1 doesn't, and the DT carries it only for
 * the apciec DARTs. Applied here before the ports go down, each word's before/after printed.
 */
#define T602X_BENCH_DART0		0x03000000	/* from rc: dart-apcie0, 0x594000000 */
#define T602X_BENCH_DART1		0x04000000	/* from rc: dart-apcie1, 0x595000000 */

static const u32 t602x_bench_dart_tunables[][3] = {
	{ 0x20c, 0xff0000b7, 0xe40000b7 },
	{ 0x220, 0x000f0f0f, 0x000f0f0f },
	{ 0x224, 0x00ffffff, 0x00080808 },
	{ 0x300, 0x00001f31, 0x00000001 },
	{ 0x308, 0x3ffffffc, 0x10000000 },
	{ 0x310, 0x3ffffffc, 0x3ffffffc },
};

static void apple_pcie_bench_t602x_dart_tunables(struct apple_pcie *pcie)
{
	struct resource *rc = platform_get_resource(to_platform_device(pcie->dev), IORESOURCE_MEM, 1);
	static const u32 offs[] = { T602X_BENCH_DART0, T602X_BENCH_DART1 };
	unsigned int d, i;

	if (!rc)
		return;
	for (d = 0; d < ARRAY_SIZE(offs); d++) {
		void __iomem *dart = ioremap_np(rc->start + offs[d], SZ_16K);
		u32 before[ARRAY_SIZE(t602x_bench_dart_tunables)];
		u32 after[ARRAY_SIZE(t602x_bench_dart_tunables)];

		if (!dart) {
			dev_err(pcie->dev, "bench: dart-apcie%u not mapped\n", d);
			continue;
		}
		for (i = 0; i < ARRAY_SIZE(t602x_bench_dart_tunables); i++) {
			const u32 *t = t602x_bench_dart_tunables[i];

			before[i] = readl(dart + t[0]);
			writel((before[i] & ~t[1]) | t[2], dart + t[0]);
			after[i] = readl(dart + t[0]);
		}
		dev_info(pcie->dev,
			 "bench: dart-apcie%u tunables: 0x20c %#x -> %#x, 0x220 %#x -> %#x, 0x224 %#x -> %#x, 0x300 %#x -> %#x, 0x308 %#x -> %#x, 0x310 %#x -> %#x\n",
			 d, before[0], after[0], before[1], after[1], before[2], after[2],
			 before[3], after[3], before[4], after[4], before[5], after[5]);
		iounmap(dart);
	}
}

static void apple_pcie_bench_t602x_sleep(struct apple_pcie *pcie)
{
	struct pci_host_bridge *bridge = pci_host_bridge_from_priv(pcie);
	struct apple_pcie_port *port;

	/* What bench_resume puts back: the ports' stream map and IRQ mask, before anything is cleared. */
	list_for_each_entry(port, &pcie->ports, entry) {
		int i;

		port->saved_intmask = apple_pcie_port_readl(port, PORT_INTMSK);
		for_each_set_bit(i, port->sid_map, port->sid_map_sz)
			port->saved_rid2sid[i] = apple_pcie_port_readl(port, port_rid2sid_offset(port, i));
	}

	if (bench_gpfix & T602X_BENCH_GPFIX_ORDER) {
		list_for_each_entry_reverse(port, &pcie->ports, entry)
			apple_pcie_bench_t602x_port_off(pcie, port, bridge->bus);
	} else {
		list_for_each_entry(port, &pcie->ports, entry)
			apple_pcie_bench_t602x_port_off(pcie, port, bridge->bus);
	}
	if (bench_gpfix & T602X_BENCH_GPFIX_LANEACK) {
		list_for_each_entry(port, &pcie->ports, entry)
			dev_info(pcie->dev, "bench: gpfix port %d lane cfg %#x before the root complex\n",
				 port->idx, readl(port->phy + PHY_LANE_CFG));
	}
	apple_pcie_bench_t602x_rc_off(pcie);
}

/*
 * bench_resume (Tanabota note 77 §14.8, note 78 §3.1): after a bench_perst=3/4 entry,
 * apple_pcie_resume_noirq for a non-tunneled host would return without touching it, and the root
 * complex stays down: an access to the internal DARTs then raises an SError (S3-10/11 under the HV:
 * L2C_ERR_ADR in a DART at 0x5_xxxx_xxxx). The DARTs resume BEFORE this host in every phase:
 * fw_devlink makes them suppliers through iommu-map. So the entry marks them host_resumes
 * (apple_dart_set_host_resumes()): after a firmware-driven sleep their noirq resume gates them, and
 * the end of this restores them (apple_dart_host_resume()). Without suspend_via_firmware their
 * restore is the normal phase's, which comes after this anyway. Here:
 * - the shared PHY and the axi2af bridge in the reverse order of apple_pcie_bench_t602x_rc_off();
 * - each port as probe brings a link up, without pwren: the entry kept it high, and it is an SMC
 *   GPIO, which isn't served before the SMC resumes; PERST# is pinctrl's;
 * - the RID2SID entries and IRQ mask saved at the entry, the port IRQs enabled, the LTSSM started
 *   and the link polled (device interrupts are still off).
 * The root ports' and endpoints' config space comes back in their own noirq resume.
 */
/* Bench (note 77 §14.44): the port's MSI doorbell words, as a string for a print. */
static void apple_pcie_bench_msi_words(struct apple_pcie_port *port, char *buf, size_t len)
{
	struct apple_pcie *pcie = port->pcie;

	snprintf(buf, len, "MSIADDR %#x HI %#x MSICFG %#x MSIMAP[0] %#x",
		 apple_pcie_port_readl(port, pcie->hw->port_msiaddr),
		 pcie->hw->port_msiaddr_hi ?
			apple_pcie_port_readl(port, pcie->hw->port_msiaddr_hi) : 0,
		 apple_pcie_port_readl(port, PORT_MSICFG),
		 pcie->hw->port_msimap ?
			apple_pcie_port_readl(port, pcie->hw->port_msimap) : 0);
}

/*
 * Bench (note 77 §14.44): after the wake the port's MSI doorbell is gone, and a GL9755 MSI to
 * 0xfffff000 faults in its DART (b1h2, 6 of 6 SD wakes). Probe's MSI setup again, as the tunnel
 * path's apple_pcie_tunnel_restore_irq_hw() does it, with apple_sleep.hybrid bit 13. The words
 * are printed before and after in either case.
 */
static void apple_pcie_bench_t602x_msi(struct apple_pcie *pcie, struct apple_pcie_port *port)
{
	char before[96], after[96];
	bool restore = apple_sleep_bench_hybrid() & APPLE_SLEEP_HYBRID_PCIE_MSI;
	u32 value = 0;
	int i;

	apple_pcie_bench_msi_words(port, before, sizeof(before));
	if (restore) {
		apple_pcie_port_writel(port, lower_32_bits(DOORBELL_ADDR), pcie->hw->port_msiaddr);
		if (pcie->hw->port_msiaddr_hi)
			apple_pcie_port_writel(port, 0, pcie->hw->port_msiaddr_hi);
		if (pcie->hw->port_msimap) {
			for (i = 0; i < pcie->nvecs; i++)
				apple_pcie_port_writel(port,
					FIELD_PREP(PORT_MSIMAP_TARGET, i) | PORT_MSIMAP_ENABLE,
					pcie->hw->port_msimap + 4 * i);
		} else {
			apple_pcie_port_writel(port, 0, PORT_MSIBASE);
			value = ilog2(pcie->nvecs) << PORT_MSICFG_L2MSINUM_SHIFT;
		}
		apple_pcie_port_writel(port, value | PORT_MSICFG_EN, PORT_MSICFG);
	}
	apple_pcie_bench_msi_words(port, after, sizeof(after));
	dev_info(pcie->dev, "bench: resume port %d MSI %s: %s -> %s\n", port->idx,
		 restore ? "restored" : "as found", before, after);
}

#define DWC_PORT_DEBUG0_LTSSM		GENMASK(5, 0)

static u32 apple_pcie_port_ltssm(struct apple_pcie *pcie, struct apple_pcie_port *port)
{
	return FIELD_GET(DWC_PORT_DEBUG0_LTSSM,
			 readl_relaxed(pcie->cfg->win + (PCI_DEVFN(port->idx, 0) << 12) +
				       DWC_PORT_DEBUG0));
}

static int apple_pcie_bench_t602x_port_on(struct apple_pcie *pcie, struct apple_pcie_port *port)
{
	void __iomem *lane = port->phy + PHY_LANE_CFG;
	u32 lane0 = readl(lane), stat;
	int ret, i;

	rmw_set(PORT_APPCLK_EN, port->base + PORT_APPCLK);
	if (port->perst_gpio)
		gpiod_set_value_cansleep(port->perst_gpio, 1);
	writel(readl(lane) & ~PHY_LANE_CFG_B14, lane);
	ret = apple_pcie_setup_refclk(pcie, port);
	if (ret) {
		dev_err(pcie->dev, "bench: resume port %d refclk %d (lane cfg %#x -> %#x)\n",
			port->idx, ret, lane0, readl(lane));
		return ret;
	}
	usleep_range(100, 200);
	rmw_set(PORT_PERST_OFF, port->base + pcie->hw->port_perst);
	if (port->perst_gpio)
		gpiod_set_value_cansleep(port->perst_gpio, 0);
	msleep(100);
	ret = readl_relaxed_poll_timeout(port->base + PORT_STATUS, stat, stat & PORT_STATUS_READY,
					 100, 250000);
	if (ret) {
		dev_err(pcie->dev, "bench: resume port %d not ready (status %#x)\n", port->idx, stat);
		return ret;
	}
	if (pcie->hw->port_refclk)
		rmw_clear(PORT_REFCLK_CGDIS, port->base + pcie->hw->port_refclk);
	else
		rmw_set(PHY_LANE_CFG_REFCLKCGEN, lane);
	rmw_clear(PORT_APPCLK_CGDIS, port->base + PORT_APPCLK);

	for_each_set_bit(i, port->sid_map, port->sid_map_sz)
		apple_pcie_rid2sid_write(port, i, port->saved_rid2sid[i]);
	apple_pcie_bench_t602x_msi(pcie, port);
	apple_pcie_port_writel(port, port->saved_intmask, PORT_INTMSK);
	apple_pcie_port_enable_irq(port);

	apple_pcie_port_writel(port, PORT_LTSSMCTL_START, PORT_LTSSMCTL);
	ret = readl_relaxed_poll_timeout(port->base + PORT_LINKSTS, stat, stat & PORT_LINKSTS_UP,
					 1000, link_up_timeout * 1000);
	dev_info(pcie->dev, "bench: resume port %d: lane cfg %#x -> %#x, link %s (linksts %#x, LTSSM %#x)\n",
		 port->idx, lane0, readl(lane), ret ? "DOWN" : "up", stat,
		 apple_pcie_port_ltssm(pcie, port));
	/* A port without an endpoint stays down, as at probe: not an error. */
	return 0;
}

/* bench_resume under suspend_via_firmware: a DART's state saved by its consumer, then its commands gated */
static int apple_pcie_bench_dart_save_gate(struct device *dart)
{
	int ret = apple_dart_state_save(dart);

	apple_dart_quiesce_commands(dart);
	return ret;
}

/*
 * bench_resume: each available DART named in the host's iommu-map (t602x: pcie0_dart_0..3), once. A disabled one
 * (j416s: dart_2 and dart_3, no port) is skipped, not an error. *done of *total returned 0.
 */
static int apple_pcie_bench_for_each_dart(struct apple_pcie *pcie, int (*fn)(struct device *),
					  unsigned int *done, unsigned int *total)
{
	struct device_node *np = pcie->dev->of_node, *seen[8] = {};
	int n = of_property_count_u32_elems(np, "iommu-map"), ns = 0, ret = 0, i, k;

	for (k = 0; n > 0 && k < n / 4; k++) {
		/* <rid-base iommu iommu-base length>: the phandle is cell 4k + 1 */
		struct device_node *d = of_parse_phandle(np, "iommu-map", 4 * k + 1);
		struct platform_device *pdev;
		bool dup = false;
		int err;

		if (!d)
			continue;
		if (!of_device_is_available(d)) {
			of_node_put(d);
			continue;
		}
		for (i = 0; i < ns; i++)
			dup |= seen[i] == d;
		if (dup || ns == ARRAY_SIZE(seen)) {
			of_node_put(d);
			continue;
		}
		seen[ns++] = d;
		(*total)++;
		pdev = of_find_device_by_node(d);
		if (!pdev) {
			ret = ret ?: -ENODEV;
			continue;
		}
		err = fn(&pdev->dev);
		put_device(&pdev->dev);
		if (!err)
			(*done)++;
		else if (!ret)
			ret = err;
	}
	for (i = 0; i < ns; i++)
		of_node_put(seen[i]);
	return ret;
}

static int apple_pcie_bench_t602x_resume(struct apple_pcie *pcie)
{
	struct resource *rc = platform_get_resource(to_platform_device(pcie->dev), IORESOURCE_MEM, 1);
	struct apple_pcie_port *port;
	void __iomem *phy, *axi;
	u32 v, phy0, phy40, axi0;
	int ack0, ack1, ret = 0;

	if (!rc)
		return -ENODEV;
	phy = ioremap_np(rc->start + T602X_BENCH_PHY_SHARED, SZ_16K);
	axi = ioremap_np(rc->start + T602X_BENCH_AXI2AF, SZ_16K);
	if (!phy || !axi) {
		dev_err(pcie->dev, "bench: resume: shared PHY / axi2af not mapped\n");
		ret = -ENOMEM;
		goto out;
	}
	phy0 = readl(phy);
	phy40 = readl(phy + 4);
	axi0 = readl(axi + T602X_BENCH_AXI2AF_CTL);

	/* _disableRootComplex backwards */
	writel(readl(axi + T602X_BENCH_AXI2AF_CTL) | BIT(16), axi + T602X_BENCH_AXI2AF_CTL);
	writel(readl(phy + 4) | BIT(0), phy + 4);
	writel(readl(phy + 4) | BIT(4), phy + 4);
	udelay(10);
	writel(readl(phy) | BIT(9) | BIT(8), phy);
	udelay(1);
	writel(readl(phy) | PHY_LANE_CFG_REFCLK0REQ, phy);
	ack0 = readl_poll_timeout(phy, v, v & PHY_LANE_CFG_REFCLK0ACK, 1, 10000);
	udelay(1);
	writel(readl(phy) | PHY_LANE_CFG_REFCLK1REQ, phy);
	ack1 = readl_poll_timeout(phy, v, v & PHY_LANE_CFG_REFCLK1ACK, 1, 10000);
	udelay(1);
	writel(readl(phy) & ~T602X_BENCH_PHY_CTRL_RESET, phy);
	udelay(10);
	dev_info(pcie->dev,
		 "bench: resume: root complex on: shared PHY %#x -> %#x (ack0 %d, ack1 %d), +4 %#x -> %#x, axi2af +0x400 %#x -> %#x\n",
		 phy0, readl(phy), ack0, ack1, phy40, readl(phy + 4), axi0,
		 readl(axi + T602X_BENCH_AXI2AF_CTL));

	list_for_each_entry(port, &pcie->ports, entry) {
		ret = apple_pcie_bench_t602x_port_on(pcie, port);
		if (ret)
			break;
	}
	/*
	 * The root complex is back: the DARTs their noirq resume gated restore now. Also after a
	 * port that didn't come back (rv-usb4, batch 5): the shared PHY and axi2af are on by here,
	 * so the DART blocks answer, and left gated every internal DART would refuse all commands
	 * until the next boot. Only a root complex that never came back (out:) leaves them gated.
	 */
	{
		unsigned int nd = 0, nt = 0;
		int dret = apple_pcie_bench_for_each_dart(pcie, apple_dart_host_resume, &nd, &nt);

		dev_info(pcie->dev, "bench: resume: DARTs restored after the root complex%s: %u of %u, %d\n",
			 ret ? " (a port failed)" : "", nd, nt, dret);
	}
out:
	if (axi)
		iounmap(axi);
	if (phy)
		iounmap(phy);
	return ret;
}


static int apple_pcie_suspend_noirq(struct device *dev)
{
	struct apple_pcie *pcie = apple_pcie_lookup(dev);

	if (bench_perst == 3 || bench_perst == 4) {
		if (pcie->hw != &t602x_hw) {
			dev_err(dev, "bench: bench_perst=%u is t602x's sequence\n", bench_perst);
			return 0;
		}
		if (bench_perst == 4)
			apple_pcie_bench_t602x_dart_tunables(pcie);
		/* bench_resume: the DARTs wait for this host's resume (note 78 §3.1) */
		if (bench_resume) {
			unsigned int nd = 0, nt = 0;
			int dret = apple_pcie_bench_for_each_dart(pcie, apple_dart_set_host_resumes,
								  &nd, &nt);

			dev_info(dev, "bench: DARTs held for the host's resume: %u of %u, %d\n",
				 nd, nt, dret);
			/*
			 * Note 79: under suspend_via_firmware the DARTs' own save is their noirq,
			 * after this teardown (they are suppliers: suspended after their
			 * consumer), and their blocks no longer answer then (pd691: 0x594001000).
			 * Save them now and gate them, so their noirq suspend leaves them alone;
			 * the resume's host_resume restores them.
			 */
			if (pm_suspend_via_firmware()) {
				nd = 0;
				nt = 0;
				dret = apple_pcie_bench_for_each_dart(pcie,
								      apple_pcie_bench_dart_save_gate,
								      &nd, &nt);
				dev_info(dev, "bench: DARTs saved and gated before the root complex: %u of %u, %d\n",
					 nd, nt, dret);
			}
		}
		apple_pcie_bench_t602x_sleep(pcie);
		pcie->bench_rc_off = true;
		return 0;
	}

	if (s2idle_hold_domains && pm_suspend_no_platform() && pcie->num_pds)
		return apple_pcie_hold_domains(pcie);
	return 0;
}

static int apple_pcie_resume_noirq(struct device *dev)
{
	struct apple_pcie *pcie = apple_pcie_lookup(dev);

	/* The domain's hold for the sleep ends first, whatever follows. */
	apple_pcie_release_domains(pcie);
	if (pcie->bench_rc_off) {
		pcie->bench_rc_off = false;
		if (bench_resume)
			return apple_pcie_bench_t602x_resume(pcie);
		dev_info(dev, "bench: the root complex stays down (bench_resume=0)\n");
	}
	return 0;
}

static const struct dev_pm_ops apple_pcie_pm_ops = {
	NOIRQ_SYSTEM_SLEEP_PM_OPS(apple_pcie_suspend_noirq, apple_pcie_resume_noirq)
};

static const struct of_device_id apple_pcie_of_match[] = {
	{ .compatible = "apple,t6020-pcie",	.data = &t602x_hw },
	{ .compatible = "apple,pcie",		.data = &t8103_hw },
	{ }
};
MODULE_DEVICE_TABLE(of, apple_pcie_of_match);

static struct platform_driver apple_pcie_driver = {
	.probe	= apple_pcie_probe,
	.driver	= {
		.name			= "pcie-apple",
		.of_match_table		= apple_pcie_of_match,
		.suppress_bind_attrs	= true,
		.pm			= pm_sleep_ptr(&apple_pcie_pm_ops),
	},
};
module_platform_driver(apple_pcie_driver);

MODULE_DESCRIPTION("Apple PCIe host bridge driver");
MODULE_LICENSE("GPL v2");
