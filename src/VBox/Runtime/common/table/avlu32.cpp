/* $Id: avlu32.cpp 98103 2023-01-17 14:15:46Z vboxsync $ */
/** @file
 * IPRT - AVL tree, uint32_t, unique keys.
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

#ifndef NOFILEID
static const char szFileId[] = "Id: kAVLULInt.c,v 1.4 2003/02/13 02:02:38 bird Exp $";
#endif


/*********************************************************************************************************************************
*   Defined Constants And Macros                                                                                                 *
*********************************************************************************************************************************/
/*
 * AVL configuration.
 */
#define KAVL_FN(a)                  RTAvlU32##a
#define KAVL_MAX_STACK              27  /* Up to 2^24 nodes. */
#define KAVL_CHECK_FOR_EQUAL_INSERT 1   /* No duplicate keys! */
#define KAVLNODECORE                AVLU32NODECORE
#define PKAVLNODECORE               PAVLU32NODECORE
#define PPKAVLNODECORE              PPAVLU32NODECORE
#define KAVLKEY                     AVLU32KEY
#define PKAVLKEY                    PAVLU32KEY
#define KAVLENUMDATA                AVLU32ENUMDATA
#define PKAVLENUMDATA               PAVLU32ENUMDATA
#define PKAVLCALLBACK               PAVLU32CALLBACK


/*
 * AVL Compare macros
 */
#define KAVL_G(key1, key2)          ( (key1) >  (key2) )
#define KAVL_E(key1, key2)          ( (key1) == (key2) )
#define KAVL_NE(key1, key2)         ( (key1) != (key2) )


/*********************************************************************************************************************************
*   Header Files                                                                                                                 *
*********************************************************************************************************************************/
#include <iprt/avl.h>
#include <iprt/assert.h>
#include <iprt/errcore.h>

/*
 * Include the code.
 */
#define SSToDS(ptr) ptr
#define KMAX RT_MAX
#define kASSERT Assert
#include "avl_Base.cpp.h"
#include "avl_Get.cpp.h"
#include "avl_GetBestFit.cpp.h"
#include "avl_RemoveBestFit.cpp.h"
#include "avl_DoWithAll.cpp.h"
#include "avl_Destroy.cpp.h"
