/* $Id: RTSemEventMultiWait-2-ex-generic.cpp 98103 2023-01-17 14:15:46Z vboxsync $ */
/** @file
 * IPRT - RTSemEventMultiWait, implementation based on RTSemEventMultiWaitEx.
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
#define LOG_GROUP RTLOGGROUP_SEM
#define RTSEMEVENTMULTI_WITHOUT_REMAPPING
#include <iprt/semaphore.h>
#include "internal/iprt.h"

#include <iprt/errcore.h>
#include <iprt/assert.h>


RTDECL(int)  RTSemEventMultiWait(RTSEMEVENTMULTI hEventMultiSem, RTMSINTERVAL cMillies)
{
    int rc;
    if (cMillies == RT_INDEFINITE_WAIT)
        rc = RTSemEventMultiWaitEx(hEventMultiSem, RTSEMWAIT_FLAGS_RESUME | RTSEMWAIT_FLAGS_INDEFINITE, 0);
    else
        rc = RTSemEventMultiWaitEx(hEventMultiSem,
                                   RTSEMWAIT_FLAGS_RESUME | RTSEMWAIT_FLAGS_RELATIVE | RTSEMWAIT_FLAGS_MILLISECS,
                                   cMillies);
    Assert(rc != VERR_INTERRUPTED);
    return rc;
}
RT_EXPORT_SYMBOL(RTSemEventMultiWait);

