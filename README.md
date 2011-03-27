
NAME
====

xt\_selinux - netfilter / xtables module for matching based on SELinux contexts


SYNOPSIS
========

    iptables -A <chain> -m selinux [ [!] --task-ctx <context> ]
        [ [!] --secmark-ctx <context> ] [ [!] --socket-ctx <context> ]
        [ [!] --socket-peer-ctx <context> ] [ [!] --socket-file-ctx <context> ]
        [ [!] --socket-file-owner-ctx <context> ] [ --debug ]
        <other-iptables-options>

----

    ip6tables -A <chain> -m selinux [ [!] --task-ctx <context> ]
        [ [!] --secmark-ctx <context> ] [ [!] --socket-ctx <context> ]
        [ [!] --socket-peer-ctx <context> ] [ [!] --socket-file-ctx <context> ]
        [ [!] --socket-file-owner-ctx <context> ] [ --debug ]
        <other-ip6tables-options>


WARNINGS
========

xt\_selinux has two major, fundamental problems:

* xt\_selinux is incompatible with the SELinux goals of having a single point for decision making (the SELinux security server) and a single place in which to analyze access control rules (the SELinux policy).

* xt\_selinux currently relies on private SELinux data structures that are not intended to be used outside of the SELinux LSM (in fact, xt\_selinux is also bad because it does not support Linux Security Modules).  This makes xt\_selinux fragile, prone to breaking in the future, and creates compatibility problems.

xt\_selinux was written -- despite the above problems -- to be a learning tool, in the spirit of TIMTOWTDI (There Is More Than One Way To Do It), and to encourage some additional discussions.  However, the future of xt\_selinux is uncertain.

If at all possible, please use the secure networking functionality provided by SELinux itself, rather than xt\_selinux.   The following resources may help:

* Secure networking with SELinux:
  [http://securityblog.org/brindle/2007/05/28/secure-networking-with-selinux/](http://securityblog.org/brindle/2007/05/28/secure-networking-with-selinux/)

* SECMARK tutorial:
  [http://james-morris.livejournal.com/11010.html](http://james-morris.livejournal.com/11010.html)

* Using SELInux and iptables together:
  [http://www.linux.com/learn/tutorials/421152-using-selinux-and-iptables-together](http://www.linux.com/learn/tutorials/421152-using-selinux-and-iptables-together)

* Network labeling statements:
  [http://selinuxproject.org/page/NetworkStatements](http://selinuxproject.org/page/NetworkStatements)


INSTALLATION
============

You will need to have Linux kernel version 2.6.35 or later, as well as everything needed to compile Linux kernel modules on your system (kernel header files, development tools, etc.)

Obtain xt\_selinux with the following commands:

    git clone git://github.com/markmont/xt_selinux
    cd xt_selinux

Edit Makefile and ensure that the paths for `MODULES_DIR`, `KERNEL_DIR`, and `XTABLES_DIR` are correct for your system.

Build and install xt\_selinux:

    make
    sudo make install


OPTIONS
=======

Options preceded by an exclamation point negate the comparison:  the rule will match if the security context in question is different from the one specified.

In order to match, a context supplied to an option must be in the exact canonicalized form as which it is known to the kernel.  This includes any security level (sensitivity and categories).  For example, on a Fedora 14 system running SELinux targeted policy 3.9.7-31, a context of `system_u:system_r:sshd_t` will result in the error message "invalid SELinux context" being logged by the kernel (and `iptables` will give the error "Invalid argument. Run 'dmesg' for more information.")  However, `system_u:system_r:sshd_t:s0` and `system_u:system_r:sshd_t:s0-s0:c0.c1023` will both be accepted.  The `--debug` option or the `ps -Z` command can help you determine the correct canonicalized context.

## `[!] --task-ctx <context>` ##

Match if the SELinux context of the process that generated the packet is `<context>`.  This option is primarily useful in the `OUTPUT` chain; when used in the `INPUT` chain, the task context is likely to always be `system_u:object_r:unlabeled_t:s0`.

## `[!] --secmark-ctx <context>` ##

Match if the SELinux context of the packet -- as set by the SECMARK or CONNSECMARK `iptables` targets -- is `<context>`.

## `[!] --socket-ctx <context>` ##

Match if the SELinux context of the socket associated with the packet is `<context>`.  Primarily useful in the `OUTPUT` chain.

## `[!] --socket-peer-ctx <context>` ##

Match if the SELinux context of the other end of the socket associated with the packet is `<context>`.

## `[!] --socket-file-ctx <context>` ##

Match if the SELinux context of the file of the socket associated with the packet is `<context>`.  Primarily useful in the `OUTPUT` chain.

## `[!] --socket-file-owner-ctx <context>` ##

Match if the SELinux context of the process that owns the socket file associated with the packet is `<context>`.  Primarily useful in the `OUTPUT` chain.

## `--debug` ##

Each time the xt\_selinux portion of the rule is evaluated, debugging information will be logged by the kernel at the `info` level.  This option should be used with great care, as it can result in a significant performance hit and a very large volume of log messages. Negative effects can be minimized by making the rule as specific as possible (for example, matching on an interface, protocol, and port) and specifying the xt\_selinux portion as the rule's final component.

The debugging message will contain basic information about the packet, followed by information on each of the contexts that xt\_selinux knows about:

    context-name(actual-value)               if no match was attempted
    context-name(actual-value==match-value)  if match was attempted
    context-name(actual-value!=match-value)  if ! match was attempted

For example, the following debugging output represents a rule in which only one comparison was done: for the security context of the task that generated the packet.  Since the value on both sides of the `==` are the same, we know the match succeeded.

    kern.info kernel: [317547.748404] xt_selinux: IN= OUT=eth0
    PROTO=TCP SRC=172.16.168.128 SPORT=42034 DST=10.0.0.9
    DPORT=80 task(system_u:system_r:httpd_sys_script_t:s0==
    system_u:system_r:httpd_sys_script_t:s0)
    secmark(system_u:object_r:unlabeled_t:s0)
    socket(system_u:system_r:httpd_sys_script_t:s0)
    socket_peer(system_u:object_r:unlabeled_t:s0)
    socket_file(system_u:system_r:httpd_sys_script_t:s0)
    socket_file_owner(system_u:system_r:httpd_sys_script_t:s0)

Note: in order to have the correct source and destination port numbers appear in debugging output for IPv6 packets, the ip6tables rule must contain a `-p tcp` or `-p udp` match before the selinux match.


EXAMPLES
========

* A simple example that shows how to prohibit staff from accessing the network; this would be much better done via SELinux policy.

        iptables -A OUTPUT -m selinux --task-ctx staff_u:staff_r:staff_t:s0 \
            -j REJECT
        ip6tables -A OUTPUT -m selinux --task-ctx staff_u:staff_r:staff_t:s0 \
            -j REJECT

* A complex example for httpd for an organization with the following requirements:

    - Allow httpd to serve any requests on ports 80 and 443 from any network interface.
    - Allow httpd and its scripts (CGIs) to access any resource (databases, back-end content web servers, etc.) on the local machine via the loopback interface.
    - Prohibit any other traffic from httpd.  Specifically, do not allow any access by httpd or its scripts to resources on remote (untrusted) machines.
    - Do not affect any other service or user running on the machine.

Note that it is also possible to [solve this problem by using SELinux packet
labeling](http://lists.fedoraproject.org/pipermail/selinux/2011-March/013612.html) (SECMARK).

    (The solution below covers IPv4 only, but the IPv6 rules are similar):

        # Tell SELinux to let httpd use the network.
        setsebool httpd_can_network_connect=on

        # Allow loopback device traffic to/from all services or users:
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT

        # Accept incoming web server traffic:
        iptables -A INPUT -p tcp -m multiport --dports 80,443 \
            -m conntrack --ctstate NEW -j ACCEPT
        iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

        # Silently block all other incoming traffic:
        iptables -A INPUT -j DROP

        # httpd is already allowed (by the rules above) to send any traffic
        # via the loopback device in order to access various local resources.
        # Also allow httpd to respond to incoming web server traffic (for
        # which we've already accepted the input, above).  Prohibit httpd
        # from sending any other outbound traffic.
        iptables -N HTTPD_OUT
        iptables -A OUTPUT -m selinux --task-ctx system_u:system_r:httpd_t:s0 \
            -j HTTPD_OUT
        iptables -A HTTPD_OUT -m conntrack --ctstate RELATED,ESTABLISHED \
            -j ACCEPT
        iptables -A HTTPD_OUT -j REJECT

        # Web server scripts (CGIs) are already allowed (by a rule above) to
        # send any traffic through the loopback device in order to access
        # various local resources.  But prohibit scripts from accessing
        # anything else (such as remote machines).
        iptables -A OUTPUT \
            -m selinux --task-ctx system_u:system_r:httpd_sys_script_t:s0 \
            -j REJECT

        # Permit all other services and users on the machine to send outbound
        # traffic without restriction:
        iptables -A OUTPUT -j ACCEPT


BUGS
====

xt\_selinux currently relies on private kernel data structures and thus could break at any time (or it could already be broken since the data in question is not intended to be usable or accessible outside of the SELinux security server itself).

Some of the options currently provided may not be useful.

Some additional options might be useful to match against the SELinux contexts of interfaces, packet netlabels (labeled packets sent between different machines), or XFRM.


SUPPORT
=======

Please send any questions, feedback, requests, or patches to mark@catseye.org

Additional resources may be available at [http://github.com/markmont/xt_selinux](http://github.com/markmont/xt_selinux)


SEE ALSO
========

selinux(8), semanage(8), iptables(8), ip6tables(8)


LICENSE
=======

xt\_selinux is Copyright (C) 2011 Mark Montague, mark@catseye.org

xt\_selinux is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 2 of the License, or (at your option) any later version.

xt\_selinux is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with xt\_selinux.  If not, see [http://www.gnu.org/licenses/](http://www.gnu.org/licenses/)

