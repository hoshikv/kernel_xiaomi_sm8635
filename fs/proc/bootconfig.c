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
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/uidgid.h>

static char *saved_boot_config;
static char *spoofed_boot_config;

static int boot_config_proc_show(struct seq_file *m, void *v)
{
	const char *out = saved_boot_config;

	if (spoofed_boot_config &&
	    from_kuid(&init_user_ns, current_uid()) >= 10000)
		out = spoofed_boot_config;

	if (out)
		seq_puts(m, out);
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
	{ "androidboot.vbmeta.avb_version", "1.2" },
	{ "androidboot.flash.locked", "1" },
	{ "androidboot.veritymode.managed", "yes" },
	{ "androidboot.warranty_bit", "0" },
	{ "androidboot.vbmeta.device_state", "locked" },
	{ "androidboot.veritymode", "enforcing" },
	{ "androidboot.selinux", "enforcing" },
};

/* Return the needed total length if @size is 0 */
static int __init copy_xbc_key_value_list(char *dst, size_t size, bool spoof)
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
		if (spoof) {
			for (i = 0; i < ARRAY_SIZE(bc_spoof_entries); i++) {
				if (!strcmp(key, bc_spoof_entries[i].key)) {
					matched = i;
					break;
				}
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
	if (spoof && ret >= 0) {
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

static int __init alloc_boot_config(char **out, bool spoof)
{
	int len;

	len = copy_xbc_key_value_list(NULL, 0, spoof);
	if (len <= 0)
		return len;

	*out = kzalloc(len + 1, GFP_KERNEL);
	if (!*out)
		return -ENOMEM;

	len = copy_xbc_key_value_list(*out, len + 1, spoof);
	if (len < 0) {
		kfree(*out);
		*out = NULL;
		return len;
	}
	return 0;
}

static int __init proc_boot_config_init(void)
{
	int ret;

	ret = alloc_boot_config(&saved_boot_config, false);
	if (ret < 0)
		return ret;

	ret = alloc_boot_config(&spoofed_boot_config, true);
	if (ret < 0) {
		kfree(saved_boot_config);
		saved_boot_config = NULL;
		return ret;
	}

	proc_create_single("bootconfig", 0, NULL, boot_config_proc_show);

	return 0;
}
fs_initcall(proc_boot_config_init);
