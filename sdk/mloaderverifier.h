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
/*++
THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Module Name:  

mloaderverifier.h

Abstract:

private portion of loaderverifier.h

Notes: 


--*/
   
#ifndef __M_LOADERVERIFIER_H_
#define __M_LOADERVERIFIER_H_

#if (_MSC_VER >= 1000)
#pragma once
#endif

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

#ifndef ALGIDDEF
#define ALGIDDEF
typedef unsigned int ALG_ID;
#endif

#ifndef WINCEMACRO
#error WINCEMACRO not defined __FILE__
#endif

// Handle-based calls
#ifdef KCOREDLL

// COREDLL HT_SECLOADER

#define _DIRECT_SECLOADER_CALL(err, nargs, rt, id, argt, arglist) \
    _DIRECT_HANDLE_CALL(rt, HT_SECLOADER, id, err, argt, nargs, arglist)

#define  LoaderVerifierRouting_Trap(a, b, c) \
    _DIRECT_SECLOADER_CALL((DWORD)E_FAIL, 2, HRESULT, 2, \
        (HANDLE, LPCTSTR, ACCTID*), (a, b, c))

#define LoaderVerifierAuthorize_Trap(a, b, c, d) \
    _DIRECT_SECLOADER_CALL((DWORD)E_FAIL, 3, HRESULT, 3, \
        (HANDLE, HANDLE, HANDLE, enum LV_AUTHORIZATION*), (a, b, c, d))

#define LoaderVerifierGetHash_Trap(a, b, c, d, e, f) \
    _DIRECT_SECLOADER_CALL((DWORD)E_FAIL, 5, HRESULT, 4, \
        (HANDLE, LPCWSTR, LPBYTE, DWORD, LPDWORD, LPWSTR*), (a, b, c, d, e, f))

#define LoaderVerifierGetPageHashData_Trap(a, b, c, d, e) \
    _DIRECT_SECLOADER_CALL((DWORD)E_FAIL, 4, HRESULT, 5, \
        (HANDLE, LPBYTE, DWORD, LPDWORD, LPWSTR*), (a, b, c, d, e))

#else

// COREDLL HT_SECLOADER

#define WIN32_SECLOADER_CALL(type, api, args) \
    (*(type (*) args)IMPLICIT_CALL(HT_SECLOADER, api))

#define  LoaderVerifierRouting_Trap \
    WIN32_SECLOADER_CALL(HRESULT, 2, (HANDLE hslauthnFile, LPCTSTR szChamberID, ACCTID* pAcctId))

#define LoaderVerifierAuthorize_Trap \
    WIN32_SECLOADER_CALL(HRESULT, 3, (HANDLE hslauthnFile, HANDLE hTokenCaller, HANDLE hTokenToLoad, enum LV_AUTHORIZATION* pslauthz))

#define LoaderVerifierGetHash_Trap \
    WIN32_SECLOADER_CALL(HRESULT, 4, (HANDLE hslauthnFile, LPCWSTR pszHashAlgorithm, LPBYTE pbHash, DWORD cbHash, LPDWORD pcbHash, LPWSTR* ppszHashAlgorithm))

#define LoaderVerifierGetPageHashData_Trap \
    WIN32_SECLOADER_CALL(HRESULT, 5, (HANDLE hslauthnFile, LPBYTE pbPageHashes, DWORD cbPageHashes, LPDWORD pcbPageHashes, LPWSTR* ppszHashAlgorithm))

#endif // !KCOREDLL

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // __M_LOADERVERIFIER_H_

