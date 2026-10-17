// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * /dev/sep-key: the misc device of key.rs. Unlike sep-bio, each open file has
 * state of its own (the opener's uid, from the file's credentials in the
 * initial user namespace), which the Rust side allocates at open and frees at
 * release. Ioctls run one at a time: the key store answers one request at a
 * time anyway.
 */
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uidgid.h>

#include "shim.h"

struct sep_key_chardev {
	struct miscdevice misc;
	struct mutex lock;
	void *ctx;			/* NULL once detached */
	void *(*f_open)(void *ctx, u32 uid, int *err);
	void (*f_release)(void *ctx, void *fctx);	/* ctx may be NULL */
	long (*f_ioctl)(void *ctx, void *fctx, unsigned int cmd,
			unsigned long arg);
	bool registered;
	int open_count;
};

struct sep_key_file {
	struct sep_key_chardev *d;
	void *fctx;
};

static int sep_key_fop_open(struct inode *inode, struct file *file)
{
	struct sep_key_chardev *d =
		container_of(file->private_data, struct sep_key_chardev, misc);
	struct sep_key_file *f;
	int err = 0;

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	f->d = d;

	mutex_lock(&d->lock);
	if (!d->ctx) {
		err = -ENODEV;
	} else {
		f->fctx = d->f_open(d->ctx,
				    from_kuid(&init_user_ns, file->f_cred->fsuid),
				    &err);
		if (!err)
			d->open_count++;
	}
	mutex_unlock(&d->lock);

	if (err) {
		kfree(f);
		return err;
	}
	file->private_data = f;
	return 0;
}

static int sep_key_fop_release(struct inode *inode, struct file *file)
{
	struct sep_key_file *f = file->private_data;
	struct sep_key_chardev *d = f->d;
	bool last;

	mutex_lock(&d->lock);
	d->f_release(d->ctx, f->fctx);
	d->open_count--;
	last = (d->open_count == 0) && !d->ctx;
	mutex_unlock(&d->lock);
	kfree(f);

	/* Detached while this file was open: nobody else can reach it now. */
	if (last) {
		mutex_destroy(&d->lock);
		kfree(d);
	}
	return 0;
}

static long sep_key_fop_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	struct sep_key_file *f = file->private_data;
	struct sep_key_chardev *d = f->d;
	long ret;

	mutex_lock(&d->lock);
	ret = d->ctx ? d->f_ioctl(d->ctx, f->fctx, cmd, arg) : -ENODEV;
	mutex_unlock(&d->lock);

	return ret;
}

static const struct file_operations sep_key_fops = {
	.owner = THIS_MODULE,
	.open = sep_key_fop_open,
	.release = sep_key_fop_release,
	.unlocked_ioctl = sep_key_fop_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

/* @name must outlive the registration; the Rust side passes a &'static CStr. */
void *sep_key_register(const char *name, unsigned short mode, void *ctx,
		       void *(*f_open)(void *, u32, int *),
		       void (*f_release)(void *, void *),
		       long (*f_ioctl)(void *, void *, unsigned int,
				       unsigned long))
{
	struct sep_key_chardev *d;
	int ret;

	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d)
		return NULL;

	mutex_init(&d->lock);
	d->ctx = ctx;
	d->f_open = f_open;
	d->f_release = f_release;
	d->f_ioctl = f_ioctl;

	d->misc.minor = MISC_DYNAMIC_MINOR;
	d->misc.name = name;
	d->misc.fops = &sep_key_fops;
	d->misc.mode = mode;

	ret = misc_register(&d->misc);
	if (ret) {
		mutex_destroy(&d->lock);
		kfree(d);
		return NULL;
	}
	d->registered = true;

	return d;
}

void sep_key_unregister(void *dev)
{
	struct sep_key_chardev *d = dev;
	bool free_now;

	if (!d)
		return;

	if (d->registered)
		misc_deregister(&d->misc);

	mutex_lock(&d->lock);
	d->ctx = NULL;
	free_now = (d->open_count == 0);
	mutex_unlock(&d->lock);

	if (free_now) {
		mutex_destroy(&d->lock);
		kfree(d);
	}
}
