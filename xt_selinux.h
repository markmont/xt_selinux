/*
 * xt_selinux.h
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

#ifndef _XT_SELINUX_H_match
#define _XT_SELINUX_H_match

#include <linux/types.h>

#define CTX_POOL_SIZE		256


/* enumeration of items indices for context and sid arrays */
enum {
	XTSEL_ITEM_TASK			= 0,
	XTSEL_ITEM_SECMARK		= 1,
	XTSEL_ITEM_SOCKET		= 2,
	XTSEL_ITEM_SOCKET_PEER		= 3,
	XTSEL_ITEM_SOCKET_FILE		= 4,
	XTSEL_ITEM_SOCKET_FILE_OWNER	= 5,
};
#define XTSEL_ITEMS 6


/* masks for the "match" and "invert" sets of flags */
enum {
	XTSEL_MASK_DEBUG		= 1 << 0,
	XTSEL_MASK_TASK			= 1 << 1,
	XTSEL_MASK_SECMARK		= 1 << 2,
	XTSEL_MASK_SOCKET		= 1 << 3,
	XTSEL_MASK_SOCKET_PEER		= 1 << 4,
	XTSEL_MASK_SOCKET_FILE		= 1 << 5,
	XTSEL_MASK_SOCKET_FILE_OWNER	= 1 << 6,
};


/* map item indices onto flag masks */
static const __u16 xtsel_sid_mask[XTSEL_ITEMS] = {
	XTSEL_MASK_TASK,
	XTSEL_MASK_SECMARK,
	XTSEL_MASK_SOCKET,
	XTSEL_MASK_SOCKET_PEER,
	XTSEL_MASK_SOCKET_FILE,
	XTSEL_MASK_SOCKET_FILE_OWNER,
};


struct xt_selinux_info {
	__u16 match;
	__u16 invert;

	__u16 pool_offset[XTSEL_ITEMS];

	__u16 ctx_pool_next;
	char  ctx_pool[CTX_POOL_SIZE];

	/* used by kernel: */
	__u32 sid[XTSEL_ITEMS] __attribute__((aligned(8)));
};


#define option_ctx(ITEM) (info->ctx_pool + info->pool_offset[ITEM])

#endif /*_XT_SELINUX_H_match */
