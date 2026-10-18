/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/* Copyright 2026 Dj */
/*
 * Backing-store file access. In C because the O_* flags are macro-derived and
 * absent from the Rust bindings.
 *
 * These files are the driver's own. Opens run under kernel credentials so
 * access never depends on which task triggered the operation: a keyctl(2) call
 * from an unprivileged process reaches unseal in that process's context, and
 * without this the driver could not read its own root-only store.
 */

#include <linux/cred.h>
#include <linux/blkdev.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "shim.h"

static struct file *open_as_kernel(const char *path, int flags, umode_t mode)
{
	const struct cred *old;
	struct cred *kern;
	struct file *f;
	struct path root;

	kern = prepare_kernel_cred(&init_task);
	if (!kern)
		return ERR_PTR(-ENOMEM);

	task_lock(&init_task);
	get_fs_root(init_task.fs, &root);
	task_unlock(&init_task);

	old = override_creds(kern);
	f = file_open_root(&root, path, flags, mode);
	put_cred(revert_creds(old));
	path_put(&root);

	return f;
}

/*
 * Every open below returns an error pointer, never NULL: callers tell a missing
 * file (-ENOENT) from one they could not open (EIO, ENOMEM, an LSM denial),
 * and only the first may ever be taken for "nothing stored".
 */

/*
 * Opens the store, creating it (mode 0600, the driver's own) if absent, and
 * reports whether this call created the file, so that only a new file is ever
 * initialised.
 */
void *sep_store_open_host(const char *path, bool *created)
{
	struct file *f;

	*created = false;
	f = open_as_kernel(path, O_RDWR | O_CREAT | O_EXCL | O_LARGEFILE, 0600);
	if (PTR_ERR_OR_ZERO(f) == -EEXIST)
		return open_as_kernel(path, O_RDWR | O_LARGEFILE, 0);
	if (!IS_ERR(f))
		*created = true;
	return f;
}

/*
 * Opens an existing file read-only, ERR_PTR(-ENOENT) if absent. O_RDONLY and
 * no O_CREAT so the seed cannot be created, truncated or written by mistake.
 */
void *sep_store_open_ro(const char *path)
{
	return open_as_kernel(path, O_RDONLY | O_LARGEFILE, 0);
}

void *sep_store_open_block(const char *path, int writable)
{
	struct file *f = open_as_kernel(path,
					writable ? O_RDWR | O_LARGEFILE : O_RDONLY | O_LARGEFILE,
					0);

	if (IS_ERR(f))
		return f;
	if (!S_ISBLK(file_inode(f)->i_mode) ||
	    (writable && bdev_read_only(file_bdev(f)))) {
		filp_close(f, NULL);
		return ERR_PTR(-ENODEV);
	}
	return f;
}

/*
 * Removes the leftover tmp @tmpname from @dir by name: only a regular file,
 * and never the same inode as the target @name (on 9p a rename that took
 * effect on the server but reported an error leaves the tmp's name on the
 * live file). Returns 0 once it is gone, or an error.
 */
static int unlink_tmp(struct file *dir, const char *tmpname, const char *name)
{
	struct mnt_idmap *idmap = mnt_idmap(dir->f_path.mnt);
	struct dentry *parent = dir->f_path.dentry;
	struct dentry *d, *t;
	struct inode *di, *ti;
	int err;

	err = mnt_want_write(dir->f_path.mnt);
	if (err)
		return err;
	d = start_removing(idmap, parent, &QSTR(tmpname));
	if (IS_ERR(d)) {
		err = PTR_ERR(d);
		goto out_drop;
	}
	di = d_inode(d);
	if (!d_is_reg(d)) {
		err = -EEXIST;
		goto out_end;
	}
	/* The parent is locked: the target cannot change meanwhile. */
	t = lookup_noperm(&QSTR(name), parent);
	if (IS_ERR(t)) {
		err = PTR_ERR(t);
		goto out_end;
	}
	ti = d_inode(t);
	if (ti && (ti == di || (ti->i_sb == di->i_sb && ti->i_ino == di->i_ino)))
		err = -EEXIST;
	dput(t);
	if (err)
		goto out_end;
	err = security_path_unlink(&dir->f_path, d);
	if (!err)
		err = vfs_unlink(idmap, d_inode(parent), d, NULL);
out_end:
	end_removing(d);
out_drop:
	mnt_drop_write(dir->f_path.mnt);
	if (err)
		pr_err("apple-sep: cannot remove the leftover %s (%d)\n", tmpname, err);
	return err;
}

/*
 * The temporary of sep_store_replace(), always created fresh (O_EXCL): a
 * leftover of an earlier replace cut short is removed first. Its owner and
 * mode are not checked, as legacy 9p reports every file as uid -2.
 */
static struct file *open_tmp(const struct path *root, struct file *dir,
			     const char *tmp, const char *tmpname,
			     const char *name)
{
	const int flags = O_WRONLY | O_NOFOLLOW | O_LARGEFILE | O_CREAT | O_EXCL;
	struct file *f;
	int err;

	f = file_open_root(root, tmp, flags, 0600);
	if (PTR_ERR_OR_ZERO(f) != -EEXIST)
		return f;
	err = unlink_tmp(dir, tmpname, name);
	if (err)
		return ERR_PTR(err);
	return file_open_root(root, tmp, flags, 0600);
}

static int write_all(struct file *f, const void *buf, size_t len)
{
	loff_t pos = 0;

	while (pos < len) {
		ssize_t n = kernel_write(f, buf + pos, len - pos, &pos);

		if (n < 0)
			return n;
		if (n == 0)
			return -EIO;
	}
	return 0;
}

/*
 * Renames @tmpf's dentry, which must sit in @dir, to @name in @dir; @flags
 * is 0 or RENAME_NOREPLACE. *@called says whether vfs_rename() ran: until it
 * does the tmp is still only the tmp.
 */
static int rename_into(struct file *dir, struct file *tmpf, const char *name,
		       unsigned int flags, bool *called)
{
	struct renamedata rd = {
		.mnt_idmap = mnt_idmap(dir->f_path.mnt),
		.old_parent = dir->f_path.dentry,
		.new_parent = dir->f_path.dentry,
		.flags = flags,
	};
	int err;

	if (tmpf->f_path.mnt != dir->f_path.mnt)
		return -EXDEV;
	err = mnt_want_write(dir->f_path.mnt);
	if (err)
		return err;
	err = start_renaming_dentry(&rd, 0, tmpf->f_path.dentry, &QSTR(name));
	if (!err) {
		/*
		 * RENAME_NOREPLACE took effect in the lookup: -EEXIST for an
		 * existing target, and the parent stays locked until the rename,
		 * so none appears meanwhile. Not passed on: some filesystems
		 * (9p) refuse every rename flag.
		 */
		rd.flags = 0;
		err = security_path_rename(&dir->f_path, rd.old_dentry,
					   &dir->f_path, rd.new_dentry, 0);
		if (!err) {
			*called = true;
			err = vfs_rename(&rd);
		}
		end_renaming(&rd);
	}
	mnt_drop_write(dir->f_path.mnt);
	return err;
}

/*
 * Replaces the whole of @path with @len bytes from @buf, atomically: the bytes
 * go to "<path>.tmp" (mode 0600), which is synced and then renamed over @path,
 * and the directory is synced. A crash or an error at any point leaves either
 * the previous file or the new one, never a torn mix, and a failed replace
 * leaves the previous file as it was. Once the rename is done the replace has
 * succeeded: a failed directory sync is only logged.
 *
 * With @noreplace the rename is RENAME_NOREPLACE: a create that never
 * overwrites, -EEXIST if @path exists, and a crash leaves no partial @path.
 *
 * Refuses a directory on tmpfs or ramfs: a record there would be gone at the
 * next boot (an initramfs, or /var/lib not mounted yet), and for the driver's
 * keybags a record that does not last orphans what it names.
 */
/*
 * One replace at a time, driver-wide: two of one path would share the tmp,
 * and one could truncate it while the other renames it into place.
 */
static DEFINE_MUTEX(sep_store_replace_lock);

int sep_store_replace(const char *path, const void *buf, size_t len,
		      bool noreplace)
{
	const struct cred *old;
	struct file *dir, *tmpf;
	struct cred *kern;
	const char *name;
	struct path root;
	char *dpath, *tmp;
	unsigned long magic;
	bool rename_called = false;
	int err;

	name = strrchr(path, '/');
	if (!name || name == path || !name[1])
		return -EINVAL;
	dpath = kstrndup(path, name - path, GFP_KERNEL);
	tmp = kasprintf(GFP_KERNEL, "%s.tmp", path);
	kern = prepare_kernel_cred(&init_task);
	if (!dpath || !tmp || !kern) {
		err = -ENOMEM;
		goto out_free;
	}
	name++;

	mutex_lock(&sep_store_replace_lock);
	task_lock(&init_task);
	get_fs_root(init_task.fs, &root);
	task_unlock(&init_task);
	old = override_creds(kern);

	dir = file_open_root(&root, dpath, O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(dir)) {
		err = PTR_ERR(dir);
		goto out_creds;
	}
	magic = dir->f_path.dentry->d_sb->s_magic;
	if (magic == TMPFS_MAGIC || magic == RAMFS_MAGIC) {
		err = -EROFS;
		goto out_dir;
	}

	tmpf = open_tmp(&root, dir, tmp, strrchr(tmp, '/') + 1, name);
	if (IS_ERR(tmpf)) {
		err = PTR_ERR(tmpf);
		goto out_dir;
	}
	err = write_all(tmpf, buf, len);
	if (!err)
		err = vfs_fsync(tmpf, 0);
	if (!err)
		err = rename_into(dir, tmpf, name,
				  noreplace ? RENAME_NOREPLACE : 0, &rename_called);
	filp_close(tmpf, NULL);
	/*
	 * A failed replace removes its tmp, which may hold a secret, unless
	 * vfs_rename() ran: then its name may be the live file's (9p), and the
	 * next replace sorts it out with the same inode check.
	 */
	if (err && !rename_called)
		unlink_tmp(dir, strrchr(tmp, '/') + 1, name);
	/*
	 * The rename is done, so the new record is the file now: a directory
	 * that cannot be synced (9p's has no fsync and answers -EINVAL) is
	 * only less durable, never a failed replace.
	 */
	if (!err) {
		int serr = vfs_fsync(dir, 0);

		/* -EINVAL, -EOPNOTSUPP: this filesystem has no directory sync */
		if (serr == -EINVAL || serr == -EOPNOTSUPP)
			pr_warn_ratelimited("apple-sep: %s: no directory sync (%d); the file is replaced\n",
					    dpath, serr);
		else if (serr)
			pr_err_ratelimited("apple-sep: %s: directory sync failed (%d); the file is replaced\n",
					   dpath, serr);
	}

out_dir:
	filp_close(dir, NULL);
out_creds:
	revert_creds(old);
	path_put(&root);
	mutex_unlock(&sep_store_replace_lock);
out_free:
	if (kern)
		put_cred(kern);
	kfree(tmp);
	kfree(dpath);
	return err;
}

void sep_store_close(void *handle)
{
	if (handle)
		filp_close((struct file *)handle, NULL);
}

long long sep_store_size(void *handle)
{
	struct file *f = handle;

	if (S_ISBLK(file_inode(f)->i_mode))
		return bdev_nr_bytes(file_bdev(f));
	return i_size_read(file_inode(f));
}

long sep_store_read(void *handle, long long off, void *buf, size_t len)
{
	struct file *f = handle;
	loff_t pos = off;

	return kernel_read(f, buf, len, &pos);
}

long sep_store_write(void *handle, long long off, const void *buf,
			    size_t len)
{
	struct file *f = handle;
	loff_t pos = off;

	return kernel_write(f, buf, len, &pos);
}

int sep_store_sync(void *handle)
{
	return vfs_fsync((struct file *)handle, 0);
}
