// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * The "touch" attribute of the SEP platform device: whether the Touch ID
 * sensor waits for a finger now, and for whom, so that a desktop helper can
 * tell the user to touch it (PKCS#11 callers such as ssh say nothing while a
 * finger-gated key waits). One line:
 *
 *   idle
 *   verify sep-key uid=<uid> pid=<pid> comm=<comm> guidance=<g>   a /dev/sep-key AUTH
 *   verify sep-bio guidance=<g>                   a verify through /dev/sep-bio
 *   enrol sep-bio guidance=<g>
 *
 * <g> is none, place, lift-and-move or hold-still. <uid> and <pid> (the
 * thread group id in the initial pid namespace) are the AUTH caller's; <comm>
 * is its task name, which the task chose itself: escaped so that it holds no
 * space, '=', backslash or non-printable byte (each becomes \xNN), so it
 * cannot forge a field, and the line always ends in " guidance=<g>".
 *
 * Readable by everyone; poll() on it wakes (POLLPRI) on every change. The Rust
 * side composes the line from the Touch ID session and stores it here; a read
 * takes only this spinlock.
 */
#include <linux/device.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include "shim.h"

#define SEP_TOUCH_MAX 192

static DEFINE_SPINLOCK(sep_touch_lock);
static char sep_touch_line[SEP_TOUCH_MAX] = "idle";
static struct kobject *sep_touch_kobj;

static ssize_t touch_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	char line[SEP_TOUCH_MAX];

	spin_lock(&sep_touch_lock);
	memcpy(line, sep_touch_line, sizeof(line));
	spin_unlock(&sep_touch_lock);
	return sysfs_emit(buf, "%s\n", line);
}
static DEVICE_ATTR(touch, 0444, touch_show, NULL);

static struct attribute *sep_touch_attrs[] = {
	&dev_attr_touch.attr,
	NULL
};

static const struct attribute_group sep_touch_group = {
	.attrs = sep_touch_attrs,
};

static void sep_touch_reset(void)
{
	spin_lock(&sep_touch_lock);
	strscpy(sep_touch_line, "idle", sizeof(sep_touch_line));
	spin_unlock(&sep_touch_lock);
}

/* devres removes the attribute when the driver unbinds. */
int sep_touch_register(struct device *dev)
{
	int ret;

	sep_touch_reset();
	ret = devm_device_add_group(dev, &sep_touch_group);

	if (!ret)
		WRITE_ONCE(sep_touch_kobj, &dev->kobj);
	return ret;
}

/* Nothing waits for a finger once the driver goes: the line reads idle. */
void sep_touch_unregister(void)
{
	WRITE_ONCE(sep_touch_kobj, NULL);
	sep_touch_reset();
}

/* Stores the line and wakes pollers if it changed. */
void sep_touch_set(const char *line, size_t len)
{
	struct kobject *kobj;
	bool changed;

	len = min(len, (size_t)SEP_TOUCH_MAX - 1);
	spin_lock(&sep_touch_lock);
	changed = strlen(sep_touch_line) != len || memcmp(sep_touch_line, line, len);
	if (changed) {
		memcpy(sep_touch_line, line, len);
		sep_touch_line[len] = '\0';
	}
	spin_unlock(&sep_touch_lock);
	kobj = READ_ONCE(sep_touch_kobj);
	if (changed && kobj)
		sysfs_notify(kobj, NULL, "touch");
}

/* The calling task's name, for the line. */
size_t sep_current_comm(char *buf, size_t cap)
{
	char comm[TASK_COMM_LEN];

	get_task_comm(comm, current);
	strscpy(buf, comm, cap);
	return strnlen(buf, cap);
}

/* Its process id, as the initial pid namespace sees it. */
int sep_current_tgid(void)
{
	return task_tgid_nr(current);
}
