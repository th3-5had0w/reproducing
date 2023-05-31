/* $Id: VBoxNetDhcpdHardened.cpp 98103 2023-01-17 14:15:46Z vboxsync $ */
/** @file
 * VBoxNetDhcpd - Hardened main().
 */

/*
 * Copyright (C) 2009-2023 Oracle and/or its affiliates.
 *
 * This file is part of VirtualBox base platform packages, as
 * available from https://www.virtualbox.org.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, in version 3 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses>.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <VBox/sup.h>


int main(int argc, char **argv, char **envp)
{
    return SUPR3HardenedMain("VBoxNetDHCP", 0 /* fFlags */, argc, argv, envp);
}
