//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//
//
// Use of this sample source code is subject to the terms of the Microsoft
// license agreement under which you licensed this sample source code. If
// you did not accept the terms of the license agreement, you are not
// authorized to use this sample source code. For the terms of the license,
// please see the license agreement between you and Microsoft or, if applicable,
// see the LICENSE.RTF on your install media or the root of your tools installation.
// THE SAMPLE SOURCE CODE IS PROVIDED "AS IS", WITH NO WARRANTIES OR INDEMNITIES.
//


// This file documents the PSL interface to the Loader Verifier.

#ifndef _DEVELOPERUNLOCK_H_
#define _DEVELOPERUNLOCK_H_

#if (_MSC_VER >= 1000)
#pragma once
#endif

#include <windows.h>

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

//
// DeveloperUnlock states
//
typedef enum LV_DEVELOPERUNLOCKSTATE
{
    LV_DEVELOPERUNLOCK_STATE_DISABLED          = 0x0,
    LV_DEVELOPERUNLOCK_STATE_ENABLED           = 0x1,
} LV_DEVELOPERUNLOCKSTATE;

/// <summary>
///     Get current DeveloperUnlock enabling State
/// </summary>
/// <param name="pelvDeveloperUnlockState">
///     Pointer to LV_DEVELOPERUNLOCKSTATE variable receiving current developer unlock
///   enabling state.
/// </param>
/// <returns>
///     S_OK. - If the function succeeds
///     appropriate error - otherwise
/// </returns>
/// <remarks>
///     This function can only be called from Standard rights chamber and/or above.
/// </remarks>
HRESULT
GetDeveloperUnlockState( __out enum LV_DEVELOPERUNLOCKSTATE* pelvDeveloperUnlockState );

/// <summary>
///     Set current DeveloperUnlock enabling State
/// </summary>
/// <param name="elvDeveloperUnlockState">
///     Current developer unlock enabling state to be set
///   enabling state.
/// </param>
/// <returns>
///     S_OK. - If the function succeeds
///     appropriate error - otherwise
/// </returns>
/// <remarks>
///     This function can only be called from TCB chamber.
/// </remarks>
HRESULT
SetDeveloperUnlockState( enum LV_DEVELOPERUNLOCKSTATE elvDeveloperUnlockState );

#ifdef __cplusplus
}
#endif // __cplusplus
    
#endif