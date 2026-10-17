// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * fairydust: aurora's FileVault interface (fv_shim.c, CONFIG_APPLE_SEP_FV_INTERFACE,
 * built into the kernel with nvme-apple and blk-crypto hooks) is not ported. The driver
 * already treats a failed registration as "no FileVault" and goes on.
 */
#include <linux/errno.h>

#include "shim.h"

int sep_fv_register_v2(void *context, const struct sep_fv_ops *ops)
{
	return -ENODEV;
}

void sep_fv_unregister_v2(void *context)
{
}
