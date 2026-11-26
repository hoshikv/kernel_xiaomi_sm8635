// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>

struct cmdline_spoof_entry {
	const char *key;
	const char *val;
	bool safe_for_init;
};

static const struct cmdline_spoof_entry cmdline_spoof_entries[] = {
	{ "androidboot.verifiedbootstate=", "green", true },
	{ "androidboot.vbmeta.avb_version=", "1.2", true },
	{ "androidboot.flash.locked=", "1", true },
	{ "androidboot.veritymode.managed=", "yes", true },
	{ "androidboot.warranty_bit=", "0", true },
	{ "androidboot.vbmeta.device_state=", "locked", false },
	{ "androidboot.veritymode=", "enforcing", false },
	{ "androidboot.selinux=", "enforcing", false },
};

static char *spoofed_command_line;
static char *spoofed_command_line_init;

static char * __init build_spoofed_cmdline(bool init_only)
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
			size_t klen;

			if (init_only && !cmdline_spoof_entries[i].safe_for_init)
				continue;
			klen = strlen(cmdline_spoof_entries[i].key);
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
		if (seen[i] || (init_only && !cmdline_spoof_entries[i].safe_for_init))
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
	const char *out;

	if (is_global_init(current))
		out = spoofed_command_line_init ? spoofed_command_line_init : saved_command_line;
	else
		out = spoofed_command_line ? spoofed_command_line : saved_command_line;

	seq_puts(m, out);
	seq_putc(m, '\n');
	return 0;
}

static int __init proc_cmdline_init(void)
{
	spoofed_command_line_init = build_spoofed_cmdline(true);
	spoofed_command_line = build_spoofed_cmdline(false);
	proc_create_single("cmdline", 0, NULL, cmdline_proc_show);
	return 0;
}
fs_initcall(proc_cmdline_init);
