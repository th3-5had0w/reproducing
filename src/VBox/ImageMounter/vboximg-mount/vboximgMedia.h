/* $Id: vboximgMedia.h 98103 2023-01-17 14:15:46Z vboxsync $ $Revision: 98103 $ $Date: 2023-01-17 07:15:46 -0700 (Tue, 17 Jan 2023) $ $Author: vboxsync $ */

/** @file
 * vboximgMedia.h
 */

/*
 * Copyright (C) 2008-2023 Oracle and/or its affiliates.
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

#ifndef VBOX_INCLUDED_SRC_vboximg_mount_vboximgMedia_h
#define VBOX_INCLUDED_SRC_vboximg_mount_vboximgMedia_h
#ifndef RT_WITHOUT_PRAGMA_ONCE
# pragma once
#endif

typedef struct MEDIUMINFO
{
    char *name;
    char *uuid;
    char *location;
    char *description;
    char *state;
    char *size;
    char *format;
    int ro;
} MEDIUMINFO;

int vboximgListVMs(IVirtualBox *pVirtualBox);
char *vboximgScaledSize(size_t size);

#endif /* !VBOX_INCLUDED_SRC_vboximg_mount_vboximgMedia_h */
