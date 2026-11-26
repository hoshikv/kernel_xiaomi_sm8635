// SPDX-License-Identifier: GPL-2.0
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uidgid.h>

struct cmdline_spoof_entry {
	const char *key;
	const char *val;
};

static const struct cmdline_spoof_entry cmdline_spoof_entries[] = {
	{ "androidboot.verifiedbootstate=", "green" },
	{ "androidboot.vbmeta.avb_version=", "1.2" },
	{ "androidboot.flash.locked=", "1" },
	{ "androidboot.veritymode.managed=", "yes" },
	{ "androidboot.warranty_bit=", "0" },
	{ "androidboot.vbmeta.device_state=", "locked" },
	{ "androidboot.veritymode=", "enforcing" },
	{ "androidboot.selinux=", "enforcing" },
};

static char *spoofed_command_line;

static char * __init build_spoofed_cmdline(void)
{
	bool seen[ARRAY_SIZE(cmdline_spoof_entries)] = { false };
	size_t alloc_size, pos = 0;
	const char *p = saved_command_line;
	char *buf;
	int i;

	if (!p)
		return NULL;

	alloc_size = strlen(p) + 512;
	buf = kzalloc(alloc_size, GFP_KERNEL);
	if (!buf)
		return NULL;

	while (*p) {
		const char *tok_start, *tok_end;
		size_t tok_len;
		int matched = -1;

		while (*p == ' ')
			p++;
		if (!*p)
			break;

		tok_start = p;
		while (*p && *p != ' ')
			p++;
		tok_end = p;
		tok_len = tok_end - tok_start;

		for (i = 0; i < ARRAY_SIZE(cmdline_spoof_entries); i++) {
			size_t klen = strlen(cmdline_spoof_entries[i].key);

			if (tok_len >= klen &&
			    !strncmp(tok_start, cmdline_spoof_entries[i].key, klen)) {
				matched = i;
				break;
			}
		}

		if (pos > 0 && pos + 1 < alloc_size)
			buf[pos++] = ' ';

		if (matched >= 0) {
			seen[matched] = true;
			pos += scnprintf(buf + pos, alloc_size - pos, "%s%s",
					 cmdline_spoof_entries[matched].key,
					 cmdline_spoof_entries[matched].val);
		} else {
			size_t copy_len = min(tok_len, alloc_size - pos - 1);

			memcpy(buf + pos, tok_start, copy_len);
			pos += copy_len;
			buf[pos] = '\0';
		}
	}

	for (i = 0; i < ARRAY_SIZE(cmdline_spoof_entries); i++) {
		if (seen[i])
			continue;
		if (pos > 0 && pos + 1 < alloc_size)
			buf[pos++] = ' ';
		pos += scnprintf(buf + pos, alloc_size - pos, "%s%s",
				 cmdline_spoof_entries[i].key,
				 cmdline_spoof_entries[i].val);
	}

	return buf;
}

static int cmdline_proc_show(struct seq_file *m, void *v)
{
	const char *out = saved_command_line;

	if (spoofed_command_line &&
	    from_kuid(&init_user_ns, current_uid()) >= 10000)
		out = spoofed_command_line;

	seq_puts(m, out);
	seq_putc(m, '\n');
	return 0;
}

static int __init proc_cmdline_init(void)
{
	spoofed_command_line = build_spoofed_cmdline();
	proc_create_single("cmdline", 0, NULL, cmdline_proc_show);
	return 0;
}
fs_initcall(proc_cmdline_init);
