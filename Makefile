#
# Makefile for xt_selinux
#
# Copyright (C) 2011 Mark Montague <mark@catseye.org>
#
# This file is part of xt_selinux.
#
# xt_selinux is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 2 of the License, or (at your option)
# any later version.
#
# xt_selinux is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with xt_selinux.  If not, see <http://www.gnu.org/licenses/>.
#

# Directory where kernel modules reside on your system:
MODULES_DIR := /lib/modules/$(shell uname -r)

# Directory where kernel headers or kernel sources are on your system:
KERNEL_DIR := ${MODULES_DIR}/build

# Directory where iptables and ip6tables look for their userspace extensions:
XTABLES_DIR := /lib64/xtables


obj-m += xt_selinux.o


lib%.o: lib%.c
	gcc -O2 -Wall -D_INIT=lib$*_init -fPIC -DPIC -c -o $@ $<

lib%.so: lib%.o
	gcc -shared -o $@ $^


all:		libxt_selinux.so
	make -C ${KERNEL_DIR} M=$$PWD

install:	all modules_install
	install -p -m 0755 libxt_selinux.so ${XTABLES_DIR}

modules:
	make -C ${KERNEL_DIR} M=$$PWD $@

modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@

clean:
	make -C ${KERNEL_DIR} M=$$PWD $@
	rm -f *.o *.so

