/* $Id: bs3-cmn-ExtCtxSetMxCsr.c 98103 2023-01-17 14:15:46Z vboxsync $ */
/** @file
 * BS3Kit - Bs3ExtCtxSetMxCsr
 */

/*
 * Copyright (C) 2007-2023 Oracle and/or its affiliates.
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
#include "bs3kit-template-header.h"


#undef Bs3ExtCtxSetMxCsr
BS3_CMN_DEF(bool, Bs3ExtCtxSetMxCsr,(PBS3EXTCTX pExtCtx, uint32_t uValue))
{
    AssertCompileMembersAtSameOffset(BS3EXTCTX, Ctx.x87.MXCSR, BS3EXTCTX, Ctx.x.x87.MXCSR);
    if (   pExtCtx->enmMethod == BS3EXTCTXMETHOD_FXSAVE
        || pExtCtx->enmMethod == BS3EXTCTXMETHOD_XSAVE)
    {
        pExtCtx->Ctx.x87.MXCSR = uValue;
        return true;
    }
    return false;
}

