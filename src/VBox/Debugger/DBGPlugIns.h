/* $Id: DBGPlugIns.h 98103 2023-01-17 14:15:46Z vboxsync $ */
/** @file
 * DBGPlugIns - Debugger Plug-Ins.
 *
 * This is just a temporary static wrapper for what may eventually
 * become some fancy dynamic stuff.
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

#ifndef DEBUGGER_INCLUDED_SRC_DBGPlugIns_h
#define DEBUGGER_INCLUDED_SRC_DBGPlugIns_h
#ifndef RT_WITHOUT_PRAGMA_ONCE
# pragma once
#endif

#include <VBox/vmm/dbgf.h>

RT_C_DECLS_BEGIN

extern const DBGFOSREG g_DBGDiggerFreeBsd;
extern const DBGFOSREG g_DBGDiggerDarwin;
extern const DBGFOSREG g_DBGDiggerLinux;
extern const DBGFOSREG g_DBGDiggerOS2;
extern const DBGFOSREG g_DBGDiggerSolaris;
extern const DBGFOSREG g_DBGDiggerWinNt;

RT_C_DECLS_END

#endif /* !DEBUGGER_INCLUDED_SRC_DBGPlugIns_h */

