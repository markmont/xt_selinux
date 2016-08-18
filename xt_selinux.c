/*
 * netfilter module for matching based on SELinux security contexts.
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/ipv6.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/selinux.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter/x_tables.h>
#include "xt_selinux.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mark Montague <mark@catseye.org>");
MODULE_DESCRIPTION("Xtables: SELinux security context matching");
MODULE_ALIAS("ipt_selinux");
MODULE_ALIAS("ip6t_selinux");

#define PFX "xt_selinux: "


static const char *xtsel_ctx_label[XTSEL_ITEMS] = {
        "task",
        "secmark",
        "socket",
        "socket_peer",
        "socket_file",
        "socket_file_owner",
};


/*
 * The following three structures are copied from the Linux kernel source
 * code, security/selinux/include/objsec.h
 *
 * It is very bad to copy and use them here, but this was the only way (short
 * of trying to get an unlikely-to-be-accepted-for-several-reasons patch into
 * the mainline kernel) that I could find to access the SIDs that are this
 * module's reason for existing.
 *
 */

struct task_security_struct {
        u32 osid;               /* SID prior to last execve */
        u32 sid;                /* current SID */
        u32 exec_sid;           /* exec SID */
        u32 create_sid;         /* fscreate SID */
        u32 keycreate_sid;      /* keycreate SID */
        u32 sockcreate_sid;     /* fscreate SID */
};

struct file_security_struct {
        u32 sid;                /* SID of open file description */
        u32 fown_sid;           /* SID of file owner (for SIGIO) */
        u32 isid;               /* SID of inode at the time of file open */
        u32 pseqno;             /* Policy seqno at the time of file open */
};

struct sk_security_struct {
#ifdef CONFIG_NETLABEL
        enum {                          /* NetLabel state */
                NLBL_UNSET = 0,
                NLBL_REQUIRE,
                NLBL_LABELED,
                NLBL_REQSKB,
                NLBL_CONNLABELED,
        } nlbl_state;
        void *nlbl_secattr; /* NetLabel sec attributes */
#endif
        u32 sid;                        /* SID of this object */
        u32 peer_sid;                   /* SID of peer */
        u16 sclass;                     /* sock security class */
};


void get_proto_str(int protocol, char *proto_str)
{
	char digit[4];
	char *p;

	switch (protocol) {
	case -1:
		strcpy(proto_str, "?");
		break;
       	case IPPROTO_TCP:
		strcpy(proto_str, "TCP");
		break;
	case IPPROTO_UDP:
       	case IPPROTO_UDPLITE:
		strcpy(proto_str, "UDP");
		break;
       	case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
		strcpy(proto_str, "ICMP");
		break;
	default:
		digit[0] = '0' + (protocol % 1000 ) / 100;
		digit[1] = '0' + (protocol % 100) / 10;
		digit[2] = '0' + protocol % 10;
		digit[3] = '\0';
		p = digit;
               	if (*p == '0') { p++; }
               	if (*p == '0') { p++; }
		strcpy(proto_str, p);
		break;
	}
}


static bool xt_selinux_mt(const struct sk_buff *skb,
			  struct xt_action_param *par)
{
	const struct xt_selinux_info *info = par->matchinfo;
	const struct file *socket_file = NULL;
	struct sock *sk;
	struct sk_security_struct *sksec;
	u32 sid[XTSEL_ITEMS];
	int i;
	

	/*
         * Gather all the SIDs:
         *
         */

	memset(sid, 0, sizeof(sid));

        sid[XTSEL_ITEM_SECMARK] = skb->secmark;

	sk = skb_to_full_sk(skb);
	if (sk != NULL) {
		read_lock_bh(&sk->sk_callback_lock);
		sksec = (struct sk_security_struct *) sk->sk_security;
		if (sksec != NULL) {
			sid[XTSEL_ITEM_SOCKET] = sksec->sid;
			sid[XTSEL_ITEM_SOCKET_PEER] = sksec->peer_sid;
		}
		if (sk->sk_socket != NULL) {
			socket_file = sk->sk_socket->file;
		}
		if (socket_file != NULL) {
			const struct cred *f_cred = socket_file->f_cred;
			struct file_security_struct *fsec =
			  (struct file_security_struct *) socket_file->f_security;
			if (fsec != NULL) {
				sid[XTSEL_ITEM_SOCKET_FILE] = fsec->sid;
				sid[XTSEL_ITEM_SOCKET_FILE_OWNER] = fsec->fown_sid;
			}
			if (f_cred != NULL) {
				struct task_security_struct *tsec =
				  (struct task_security_struct *) f_cred->security;
				if (tsec != NULL) {
					sid[XTSEL_ITEM_TASK] = tsec->sid;
				}
			}
		}
		read_unlock_bh(&sk->sk_callback_lock);
	}


	/*
         * Log what we found, if asked to:
         *
         */

	if (info->match & XTSEL_MASK_DEBUG) {
		const struct iphdr *iph = ip_hdr(skb);
                int sport = 0;
		int dport = 0;
		const __be16 *pptr;
		__be16 _ports[2];
                char proto_str[5];

		if (par->fragoff == 0) {
			pptr = skb_header_pointer(skb, par->thoff,
				sizeof(_ports), _ports);
			if (pptr != NULL) {
				sport = ntohs(pptr[0]);
				dport = ntohs(pptr[1]);
			}
		}

		pr_info("IN=%s OUT=%s ",
			(par->in != NULL) ? par->in->name : "",
			(par->out != NULL) ? par->out->name : "");

		if (iph->version == 4) {
			get_proto_str(iph->protocol, proto_str);
			printk("PROTO=%s SRC=%pI4 SPORT=%u "
				"DST=%pI4 DPORT=%u ",
				proto_str, &iph->saddr, sport,
				&iph->daddr, dport);
		}
		else if (iph->version == 6) {
			const struct ipv6hdr *ip6h = ipv6_hdr(skb);
			unsigned int offset;
			int proto = ipv6_find_hdr(skb, &offset, -1, NULL, NULL);
			get_proto_str(proto, proto_str);
			printk("PROTO=%s SRC=%pI6 SPORT=%u DST=%pI6 DPORT=%u ",
				proto_str, &ip6h->saddr, sport,
				&ip6h->daddr, dport);
		}

		for (i = 0 ; i < XTSEL_ITEMS ; i++) {
			int rc = -1;
			char *ctx;
			u32 len;
			char *cmp = "";
			rc = security_secid_to_secctx(sid[i], &ctx, &len);
        		if (rc != 0) {
				ctx = "?";
			}
			if (info->match & xtsel_sid_mask[i]) {
				if (info->invert & xtsel_sid_mask[i]) {
					cmp = "!=";
				}
				else {
					cmp = "==";
				}
			}
			printk("%s(%s%s%s) ", xtsel_ctx_label[i], ctx, cmp,
				info->match & xtsel_sid_mask[i] ?
					option_ctx(i) : "");
			if (rc == 0) {
       				security_release_secctx(ctx, len);
			}
		}
		printk("\n");

	}


	/*
         * Do the match:
         *
         */

	for (i = 0 ; i < XTSEL_ITEMS ; i++) {
		if (info->match & xtsel_sid_mask[i]) {
			if ((info->sid[i] != sid[i]) ^
			    !!(info->invert & xtsel_sid_mask[i])) {
				return false;
			}
		}
	}

	return true;

}


static int xt_selinux_get_sid(char *ctx, u32 *sid)
{
	int err;

	err = security_secctx_to_secid(ctx, strlen(ctx), sid);
	if (err) {
		if (err == -EINVAL) {
			pr_info("invalid SELinux context \"%s\"\n", ctx);
		}
		return err;
	}

	if (*sid == 0) {
		pr_info("unable to map SELinux context \"%s\"\n", ctx);
		return -ENOENT;
	}

	return 0;
}


static int xt_selinux_mt_check(const struct xt_mtchk_param *par)
{
	struct xt_selinux_info *info = par->matchinfo;
	int i;
	int err;

	info->ctx_pool[CTX_POOL_SIZE - 1] = '\0';

	for (i = 0 ; i < XTSEL_ITEMS ; i++) {
		if (info->match & xtsel_sid_mask[i]) {
			err = xt_selinux_get_sid(option_ctx(i), &info->sid[i]);
			if (err) {
				return err;
			}
		}
	}

	return 0;
}


static struct xt_match xt_selinux_mt_reg __read_mostly = {
	.name       = "selinux",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.checkentry = xt_selinux_mt_check,
	.match      = xt_selinux_mt,
	.matchsize  = sizeof(struct xt_selinux_info),
	.me         = THIS_MODULE,
};


static int __init xt_selinux_mt_init(void)
{
	return xt_register_match(&xt_selinux_mt_reg);
}


static void __exit xt_selinux_mt_exit(void)
{
	xt_unregister_match(&xt_selinux_mt_reg);
}

module_init(xt_selinux_mt_init);
module_exit(xt_selinux_mt_exit);
