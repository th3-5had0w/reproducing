#!/bin/sh
# $Id: preremove.sh 98103 2023-01-17 14:15:46Z vboxsync $
## @file
# VirtualBox preremove script for Solaris Guest Additions.
#

#
# Copyright (C) 2008-2023 Oracle and/or its affiliates.
#
# This file is part of VirtualBox base platform packages, as
# available from https://www.virtualbox.org.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation, in version 3 of the
# License.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses>.
#
# The contents of this file may alternatively be used under the terms
# of the Common Development and Distribution License Version 1.0
# (CDDL), a copy of it is provided in the "COPYING.CDDL" file included
# in the VirtualBox distribution, in which case the provisions of the
# CDDL are applicable instead of those of the GPL.
#
# You may elect to license modified versions of this file under the
# terms and conditions of either the GPL or the CDDL or both.
#
# SPDX-License-Identifier: GPL-3.0-only OR CDDL-1.0
#

LC_ALL=C
export LC_ALL

LANG=C
export LANG

echo "Removing VirtualBox service..."

# stop and unregister VBoxService
/usr/sbin/svcadm disable -s virtualbox/vboxservice
# Don't need to delete, taken care of by the manifest action
# /usr/sbin/svccfg delete svc:/application/virtualbox/vboxservice:default
/usr/sbin/svcadm restart svc:/system/manifest-import:default

# stop VBoxClient
pkill -INT VBoxClient

echo "Removing VirtualBox kernel modules..."

# vboxguest.sh would've been installed, we just need to call it.
/opt/VirtualBoxAdditions/vboxguest.sh stopall silentunload

# Figure out group to use for /etc/devlink.tab (before Solaris 11 SRU6
# it was always using group sys)
group=sys
if [ -f /etc/dev/reserved_devnames ]; then
    # Solaris 11 SRU6 and later use group root (check a file which isn't
    # tainted by VirtualBox install scripts and allow no other group)
    refgroup=`LC_ALL=C /usr/bin/ls -lL /etc/dev/reserved_devnames | awk '{ print $4 }' 2>/dev/null`
    if [ $? -eq 0 -a "x$refgroup" = "xroot" ]; then
        group=root
    fi
    unset refgroup
fi

# remove devlink.tab entry for vboxguest
sed -e '/name=vboxguest/d' /etc/devlink.tab > /etc/devlink.vbox
chmod 0644 /etc/devlink.vbox
chown root:$group /etc/devlink.vbox
mv -f /etc/devlink.vbox /etc/devlink.tab

# remove the link
if test -h "/dev/vboxguest" || test -f "/dev/vboxguest"; then
    rm -f /dev/vboxdrv
fi
if test -h "/dev/vboxms" || test -f "/dev/vboxms"; then
    rm -f /dev/vboxms
fi

# Try and restore xorg.conf!
echo "Restoring X.Org..."
/opt/VirtualBoxAdditions/x11restore.pl


echo "Done."

