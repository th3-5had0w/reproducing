/* $Id: udivmoddi4.c 98103 2023-01-17 14:15:46Z vboxsync $ */
/** @file
 * IPRT - __udivmoddi4 implementation
 */

/*
 * Copyright (C) 2006-2023 Oracle and/or its affiliates.
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

#include <iprt/stdint.h>
#include <iprt/uint64.h>

uint64_t __udivmoddi4(uint64_t u64A, uint64_t u64B, uint64_t *pu64R);

/**
 * __udivmoddi4() implementation to satisfy external references from 32-bit
 * code generated by gcc-7 or later.
 *
 * @param   u64A        The divident value.
 * @param   u64B        The divisor value.
 * @param   pu64R       A pointer to the reminder. May be NULL.
 * @returns u64A / u64B
 */
uint64_t __udivmoddi4(uint64_t u64A, uint64_t u64B, uint64_t *pu64R)
{
    RTUINT64U Divident;
    RTUINT64U Divisor;
    RTUINT64U Quotient;
    RTUINT64U Reminder;
    Divident.u = u64A;
    Divisor.u  = u64B;
    Quotient.u = 0; /* shut up gcc 10 */
    Reminder.u = 0; /* shut up gcc 10 */
    RTUInt64DivRem(&Quotient, &Reminder, &Divident, &Divisor);
    if (pu64R)
        *pu64R = Reminder.u;
    return Quotient.u;
}