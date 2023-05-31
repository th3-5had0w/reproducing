/* $Id: HostAudioDeviceImpl.h 98103 2023-01-17 14:15:46Z vboxsync $ */

/** @file
 * VirtualBox COM class implementation - Host audio device implementation.
 */

/*
 * Copyright (C) 2022-2023 Oracle and/or its affiliates.
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

#ifndef MAIN_INCLUDED_HostAudioDeviceImpl_h
#define MAIN_INCLUDED_HostAudioDeviceImpl_h
#ifndef RT_WITHOUT_PRAGMA_ONCE
# pragma once
#endif

#include "HostAudioDeviceWrap.h"

class ATL_NO_VTABLE HostAudioDevice :
    public HostAudioDeviceWrap
{
public:

    DECLARE_COMMON_CLASS_METHODS(HostAudioDevice)

    HRESULT FinalConstruct();
    void FinalRelease();

    // public initializer/uninitializer for internal purposes only
    HRESULT init();
    void uninit();

private:

    // wrapped IHostAudioDevice properties

};

#endif /* !MAIN_INCLUDED_HostAudioDeviceImpl_h */

