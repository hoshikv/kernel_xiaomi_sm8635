// SPDX-License-Identifier: GPL-2.0
/*
 * /proc/bootconfig - Extra boot configuration
 */
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/bootconfig.h>
#include <linux/slab.h>

static char *saved_boot_config;

static int boot_config_proc_show(struct seq_file *m, void *v)
{
	if (saved_boot_config)
		seq_puts(m, saved_boot_config);
	return 0;
}

/* Rest size of buffer */
#define rest(dst, end) ((end) > (dst) ? (end) - (dst) : 0)

struct bootconfig_spoof_entry {
	const char *key;
	const char *val;
};

static const struct bootconfig_spoof_entry bc_spoof_entries[] = {
	{ "androidboot.verifiedbootstate", "green" },
	{ "androidboot.vbmeta.device_state", "locked" },
	{ "androidboot.vbmeta.avb_version", "1.2" },
	{ "androidboot.flash.locked", "1" },
	{ "androidboot.veritymode", "enforcing" },
	{ "androidboot.veritymode.managed", "yes" },
	{ "androidboot.warranty_bit", "0" },
	{ "androidboot.selinux", "enforcing" },
};

/* Return the needed total length if @size is 0 */
static int __init copy_xbc_key_value_list(char *dst, size_t size)
{
	bool seen[ARRAY_SIZE(bc_spoof_entries)] = { false };
	struct xbc_node *leaf, *vnode;
	char *key, *end = dst + size;
	const char *val;
	char q;
	int ret = 0, i;

	key = kzalloc(XBC_KEYLEN_MAX, GFP_KERNEL);
	if (!key)
		return -ENOMEM;

	xbc_for_each_key_value(leaf, val) {
		int matched = -1;

		ret = xbc_node_compose_key(leaf, key, XBC_KEYLEN_MAX);
		if (ret < 0)
			break;
		for (i = 0; i < ARRAY_SIZE(bc_spoof_entries); i++) {
			if (!strcmp(key, bc_spoof_entries[i].key)) {
				matched = i;
				break;
			}
		}
		if (matched >= 0) {
			seen[matched] = true;
			ret = snprintf(dst, rest(dst, end), "%s = \"%s\"\n",
				       key, bc_spoof_entries[matched].val);
			if (ret < 0)
				goto out;
			dst += ret;
			continue;
		}
		ret = snprintf(dst, rest(dst, end), "%s = ", key);
		if (ret < 0)
			break;
		dst += ret;
		vnode = xbc_node_get_child(leaf);
		if (vnode) {
			xbc_array_for_each_value(vnode, val) {
				if (strchr(val, '"'))
					q = '\'';
				else
					q = '"';
				ret = snprintf(dst, rest(dst, end), "%c%s%c%s",
					q, val, q, xbc_node_is_array(vnode) ? ", " : "\n");
				if (ret < 0)
					goto out;
				dst += ret;
			}
		} else {
			ret = snprintf(dst, rest(dst, end), "\"\"\n");
			if (ret < 0)
				break;
			dst += ret;
		}
	}
	if (ret >= 0) {
		for (i = 0; i < ARRAY_SIZE(bc_spoof_entries); i++) {
			if (seen[i])
				continue;
			ret = snprintf(dst, rest(dst, end), "%s = \"%s\"\n",
				       bc_spoof_entries[i].key,
				       bc_spoof_entries[i].val);
			if (ret < 0)
				break;
			dst += ret;
		}
	}
out:
	kfree(key);

	return ret < 0 ? ret : dst - (end - size);
}

static int __init proc_boot_config_init(void)
{
	int len;

	len = copy_xbc_key_value_list(NULL, 0);
	if (len < 0)
		return len;

	if (len > 0) {
		saved_boot_config = kzalloc(len + 1, GFP_KERNEL);
		if (!saved_boot_config)
			return -ENOMEM;

		len = copy_xbc_key_value_list(saved_boot_config, len + 1);
		if (len < 0) {
			kfree(saved_boot_config);
			return len;
		}
	}

	proc_create_single("bootconfig", 0, NULL, boot_config_proc_show);

	return 0;
}
fs_initcall(proc_boot_config_init);
