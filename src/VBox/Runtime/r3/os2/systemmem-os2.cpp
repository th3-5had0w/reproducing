/* $Id: systemmem-os2.cpp 98103 2023-01-17 14:15:46Z vboxsync $ */
/** @file
 * IPRT - RTSystemQueryTotalRam, OS/2 ring-3.
 */

/*
 * Copyright (C) 2010-2023 Oracle and/or its affiliates.
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
 * The contents of this file may alternatively be used under the terms
 * of the Common Development and Distribution License Version 1.0
 * (CDDL), a copy of it is provided in the "COPYING.CDDL" file included
 * in the VirtualBox distribution, in which case the provisions of the
 * CDDL are applicable instead of those of the GPL.
 *
 * You may elect to license modified versions of this file under the
 * terms and conditions of either the GPL or the CDDL or both.
 *
 * SPDX-License-Identifier: GPL-3.0-only OR CDDL-1.0
 */


/*********************************************************************************************************************************
*   Header Files                                                                                                                 *
*********************************************************************************************************************************/
#define INCL_DOSMISC
#define INCL_ERRORS
#include <os2.h>
#undef RT_MAX

#include <iprt/system.h>
#include "internal/iprt.h"

#include <iprt/errcore.h>
#include <iprt/assert.h>
#include <iprt/string.h>


RTDECL(int) RTSystemQueryTotalRam(uint64_t *pcb)
{
    AssertPtrReturn(pcb, VERR_INVALID_POINTER);

    ULONG cbMem;
    APIRET rc = DosQuerySysInfo(QSV_TOTPHYSMEM, QSV_TOTPHYSMEM, &cbMem, sizeof(cbMem));
    if (rc != NO_ERROR)
        return RTErrConvertFromOS2(rc);

    *pcb = cbMem;
    return VINF_SUCCESS;
}


RTDECL(int) RTSystemQueryAvailableRam(uint64_t *pcb)
{
    AssertPtrReturn(pcb, VERR_INVALID_POINTER);

    ULONG cbAvailMem;
    APIRET rc = DosQuerySysInfo(QSV_TOTAVAILMEM, QSV_TOTAVAILMEM, &cbAvailMem, sizeof(cbAvailMem));
    if (rc != NO_ERROR)
        return RTErrConvertFromOS2(rc);

    *pcb = cbAvailMem;
    return VINF_SUCCESS;
}

