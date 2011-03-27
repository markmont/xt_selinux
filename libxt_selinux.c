/*
 * Shared library add-on to iptables/ip6tables to add support for matching
 * SELinux security contexts.
 *
 * Copyright (C) 2011 Mark Montague <mark@catseye.org>
 *
 * This file is part of xt_selinux.
 *
 * xt_selinux is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 2 of the License, or (at your option)
 * any later version.
 *
 * xt_selinux is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with xt_selinux.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include "xt_selinux.h"

#define PFX "SELinux context: "


static const struct option xt_selinux_opts[] = {
	{ .name = "task-ctx",              .has_arg = true,  .val = 't' },
	{ .name = "secmark-ctx",           .has_arg = true,  .val = 'm' },
	{ .name = "socket-ctx",            .has_arg = true,  .val = 's' },
	{ .name = "socket-peer-ctx",       .has_arg = true,  .val = 'p' },
	{ .name = "socket-file-ctx",       .has_arg = true,  .val = 'f' },
	{ .name = "socket-file-owner-ctx", .has_arg = true,  .val = 'o' },
	{ .name = "debug",                 .has_arg = false, .val = 'd' },
	{ .name = NULL }
};


static void xt_selinux_help(void)
{
	printf(
"SELinux security context options:\n"
"  [!] --task-ctx context        match SELinux context of the process\n"
"  [!] --secmark-ctx context     match SELinux context of the packet\n"
"  [!] --socket-ctx context      match SELinux context of the socket\n"
"  [!] --socket-peer-ctx context\n"
"                                match SELinux context of the socket's peer\n"
"  [!] --socket-file-ctx context\n"
"                                match SELinux context of the socket file\n"
"  [!] --socket-file-owner-ctx context\n"
"                                match SELinux context of the socket owner\n"
"      --debug                   write debugging information to syslog\n"
);
}


unsigned int xt_selinux_opt_set(struct xt_selinux_info *info,
		unsigned int *flags, unsigned int mask, int invert)
{
	unsigned int pos, len;

	if (*flags & mask) {
		xtables_error(PARAMETER_PROBLEM, PFX
			"Can only specify each option once");
	}

	*flags |= mask;
	info->match |= mask;
	if (invert) {
		info->invert |= mask;
	}

	/* See if this context string is already in the pool */
	pos = 0;
	while (pos < info->ctx_pool_next) {
		if (strcmp(info->ctx_pool + pos, optarg) == 0) {
			return pos;
		}
		pos += strlen(info->ctx_pool + pos) + 1;
	}

	/* It's not already in the pool; add it */
	pos = info->ctx_pool_next;
	len = strlen(optarg) + 1; /* include \0 in length */
	if (pos + len > CTX_POOL_SIZE) {
		xtables_error(PARAMETER_PROBLEM, PFX
			"Total length of all arguments too big");
	}

	strcpy(info->ctx_pool + pos, optarg);
	info->ctx_pool_next += len;

	return pos;

}


static int xt_selinux_parse(int c, char **argv, int invert, unsigned int *flags,
                         const void *entry, struct xt_entry_match **match)
{
	struct xt_selinux_info *info =
		(struct xt_selinux_info*)(*match)->data;

	switch (c) {
	case 't':
		info->pool_offset[XTSEL_ITEM_TASK] =
			xt_selinux_opt_set(info, flags, XTSEL_MASK_TASK,
				invert);
		break;
	case 'm':
		info->pool_offset[XTSEL_ITEM_SECMARK] =
			xt_selinux_opt_set(info, flags, XTSEL_MASK_SECMARK,
				invert);
		break;
	case 's':
		info->pool_offset[XTSEL_ITEM_SOCKET] =
			xt_selinux_opt_set(info, flags, XTSEL_MASK_SOCKET,
				invert);
		break;
	case 'p':
		info->pool_offset[XTSEL_ITEM_SOCKET_PEER] =
			xt_selinux_opt_set(info, flags, XTSEL_MASK_SOCKET_PEER,
				invert);
		break;
	case 'f':
		info->pool_offset[XTSEL_ITEM_SOCKET_FILE] =
			xt_selinux_opt_set(info, flags, XTSEL_MASK_SOCKET_FILE,
				invert);
		break;
	case 'o':
		info->pool_offset[XTSEL_ITEM_SOCKET_FILE_OWNER] =
			xt_selinux_opt_set(info, flags,
				XTSEL_MASK_SOCKET_FILE_OWNER, invert);
		break;
	case 'd':
		info->match |= XTSEL_MASK_DEBUG;
		break;
	default:
		return false;
	}

	return true;
}


static void xt_selinux_check(unsigned int flags)
{
	if (flags == 0) {
		xtables_error(PARAMETER_PROBLEM, PFX
			"must specify at least one match option");
	}
}


static void xt_selinux_print_item(const struct xt_selinux_info *info,
		char *label, __u16 flag, const char *val)
{
	if (!(info->match & flag)) {
		return;
	}
        if (info->invert & flag) {
		printf("! ");
	}
	printf("%s %s ", label, val);
}


static void xt_selinux_print(const void *ip, const struct xt_entry_match *match,
		int numeric)
{
	const struct xt_selinux_info *info =
		(struct xt_selinux_info*)(match)->data;

	printf("selinux ");
	xt_selinux_print_item(info, "task-ctx", XTSEL_MASK_TASK,
		option_ctx(XTSEL_ITEM_TASK));
	xt_selinux_print_item(info, "secmark-ctx", XTSEL_MASK_SECMARK,
		option_ctx(XTSEL_ITEM_SECMARK));
	xt_selinux_print_item(info, "socket-ctx", XTSEL_MASK_SOCKET,
		option_ctx(XTSEL_ITEM_SOCKET));
	xt_selinux_print_item(info, "socket-peer-ctx", XTSEL_MASK_SOCKET_PEER,
		option_ctx(XTSEL_ITEM_SOCKET_PEER));
	xt_selinux_print_item(info, "socket-file-ctx", XTSEL_MASK_SOCKET_FILE,
		option_ctx(XTSEL_ITEM_SOCKET_FILE));
	xt_selinux_print_item(info, "socket-file-owner-ctx",
		XTSEL_MASK_SOCKET_FILE_OWNER,
		option_ctx(XTSEL_ITEM_SOCKET_FILE_OWNER));
	if (info->match & XTSEL_MASK_DEBUG) {
		printf("debug ");
	}

}


static void xt_selinux_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_selinux_info *info =
		(struct xt_selinux_info*)match->data;

	xt_selinux_print_item(info, "--task-ctx", XTSEL_MASK_TASK,
		option_ctx(XTSEL_ITEM_TASK));
	xt_selinux_print_item(info, "--secmark-ctx", XTSEL_MASK_SECMARK,
		option_ctx(XTSEL_ITEM_SECMARK));
	xt_selinux_print_item(info, "--socket-ctx", XTSEL_MASK_SOCKET,
		option_ctx(XTSEL_ITEM_SOCKET));
	xt_selinux_print_item(info, "--socket-peer-ctx", XTSEL_MASK_SOCKET_PEER,
		option_ctx(XTSEL_ITEM_SOCKET_PEER));
	xt_selinux_print_item(info, "--socket-file-ctx", XTSEL_MASK_SOCKET_FILE,
		option_ctx(XTSEL_ITEM_SOCKET_FILE));
	xt_selinux_print_item(info, "--socket-file-owner-ctx",
		XTSEL_MASK_SOCKET_FILE_OWNER,
		option_ctx(XTSEL_ITEM_SOCKET_FILE_OWNER));
	if (info->match & XTSEL_MASK_DEBUG) {
		printf("--debug ");
	}

}


static struct xtables_match xt_selinux_match = {
	.family		= NFPROTO_UNSPEC,
	.name		= "selinux",
	.version	= XTABLES_VERSION,
	.revision	= 0,
	.size		= XT_ALIGN(sizeof(struct xt_selinux_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_selinux_info)),
	.help		= xt_selinux_help,
	.parse		= xt_selinux_parse,
	.final_check	= xt_selinux_check,
	.print		= xt_selinux_print,
	.save		= xt_selinux_save,
	.extra_opts	= xt_selinux_opts,
};


void _init(void)
{
	xtables_register_match(&xt_selinux_match);
}
