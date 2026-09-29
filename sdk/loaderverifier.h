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

#ifndef _LOADERVERIFIER_H_
#define _LOADERVERIFIER_H_

#if (_MSC_VER >= 1000)
#pragma once
#endif

#include <windows.h>
#include "bcrypt.h"       // for CNG algorithm identifiers
#include "acctid.h"

#if !defined(E_OBJECT_NOT_FOUND)
#define E_OBJECT_NOT_FOUND HRESULT_FROM_WIN32(ERROR_OBJECT_NOT_FOUND)
#endif //E_OBJECT_NOT_FOUND

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus


// {73BBBDAA-6CDB-4b55-84E7-448F5BB1F0A3}
EXTERN_C const GUID __declspec(selectany) LV_AUTHENTICATIONGUID_ROM_EXE = { 0x73bbbdaa, 0x6cdb, 0x4b55, { 0x84, 0xe7, 0x44, 0x8f, 0x5b, 0xb1, 0xf0, 0xa3 } };

// {693C5CE7-323F-443f-A2F0-94A59C7A9C65}
EXTERN_C const GUID __declspec(selectany) LV_AUTHENTICATIONGUID_ROM_DLL = { 0x693c5ce7, 0x323f, 0x443f, { 0xa2, 0xf0, 0x94, 0xa5, 0x9c, 0x7a, 0x9c, 0x65 } };

    
// {BC588B1A-D88B-40d4-BD96-12E9820F5BA6}
EXTERN_C const GUID __declspec(selectany) LV_AUTHENTICATIONGUID_PORTABLEEXECUTABLE = { 0xbc588b1a, 0xd88b, 0x40d4, { 0xbd, 0x96, 0x12, 0xe9, 0x82, 0xf, 0x5b, 0xa6 } };

// {39ADA822-9724-400b-872E-66D96644C9C2}
EXTERN_C const GUID __declspec(selectany) LV_AUTHENTICATIONGUID_CAB = { 0x39ada822, 0x9724, 0x400b, { 0x87, 0x2e, 0x66, 0xd9, 0x66, 0x44, 0xc9, 0xc2 } };

// {A60CDD56-A29F-43df-B0F8-9B8A4B71109B}
EXTERN_C const GUID __declspec(selectany) LV_AUTHENTICATIONGUID_XAP = { 0xa60cdd56, 0xa29f, 0x43df, { 0xb0, 0xf8, 0x9b, 0x8a, 0x4b, 0x71, 0x10, 0x9b } };

// The following GUID is for catalog files, which aren't currently supported
// by the loader verifier.
// {4251968E-7C55-401f-8C22-E5D8DCEC3326}
EXTERN_C const GUID __declspec(selectany) LV_AUTHENTICATIONGUID_CATALOG = { 0x4251968e, 0x7c55, 0x401f, { 0x8c, 0x22, 0xe5, 0xd8, 0xdc, 0xec, 0x33, 0x26 } };

//
// Loader Verifier Authorizations
//
typedef enum LV_AUTHORIZATION
{
    LV_AUTHORIZATION_DENIED                     = 0x0,
    LV_AUTHORIZATION_EXECUTE                    = 0x1
} LV_AUTHORIZATION;

//
// Loader Verifier Access Mask
//
#define LV_ACCESS_NONE                          0x000
#define LV_ACCESS_ALLOW                         0x001
#define LV_ACCESS_BLOCK                         0x002
#define LV_ACCESS_LOAD                          0x004
#define LV_ACCESS_EXECUTE                       0x008

//
// Error code specific to Loader Verifier
//
#define FACILITY_LV                              (0x400)

// The file is blocked by application block-list security policy.
#define LV_E_BLOCKED                             MAKE_HRESULT(SEVERITY_ERROR, FACILITY_LV, 0x0001)

// The file is not digitally signed.
#define LV_E_NO_SIGNATURE                        MAKE_HRESULT(SEVERITY_ERROR, FACILITY_LV, 0x0002)

// The file has been tampered with.
#define LV_E_TAMPERED                            MAKE_HRESULT(SEVERITY_ERROR, FACILITY_LV, 0x0003)

// The signing certificate or one of the certificates in the trust chain is expired.
#define LV_E_CERTIFICATE_EXPIRED                 MAKE_HRESULT(SEVERITY_ERROR, FACILITY_LV, 0x0004)

// The signing certificate or one of the certificates in the trust chain is not trusted.
#define LV_E_CERTIFICATE_NOT_TRUSTED             MAKE_HRESULT(SEVERITY_ERROR, FACILITY_LV, 0x0005)

// The signing certificate or one of the certificates in the trust chain violated its usage constraint.
#define LV_E_CERTIFICATE_USAGE_VIOLATION         MAKE_HRESULT(SEVERITY_ERROR, FACILITY_LV, 0x0006)

// The signing certificate is not chained to a specific certificate required by security policy.
#define LV_E_NOT_CHAINED_TO_REQUIRED_CERTIFICATE MAKE_HRESULT(SEVERITY_ERROR, FACILITY_LV, 0x0007)

// The file is restricted from being launched by the calling chamber to the target chamber by security policy
#define LV_E_CHAMBER_CAN_NOT_LAUNCH              MAKE_HRESULT(SEVERITY_ERROR, FACILITY_LV, 0x0008)

// The file has been restricted by security policy such that it can only be launched into one specific chamber
#define LV_E_RESTRICTED_TO_LAUNCH                MAKE_HRESULT(SEVERITY_ERROR, FACILITY_LV, 0x0009)

// The signing certificate or one of the certificates in the trust chain has been revoked
#define LV_E_CERT_REVOKED                        MAKE_HRESULT(SEVERITY_ERROR, FACILITY_LV, 0x000A)


/// <summary>
///     Obtains authentication information for the file.
/// </summary>
/// <param name="guidAuthClass">
///     Indicates the type of file that should be authenticated.
/// </param>
/// <param name="hFile">
///     Handle to the file to be authenticated. This may be NULL for some file
///     types (e.g. SL_AUTHENTICATIONCLASS_ROMMODULE).
/// </param>
/// <param name="szFilePath">
///     Full pathname of the file that is to be authenticated.
/// </param>
/// <param name="szHashHint">
///     The caller can specify a CNG algorithm identifier here to request that
///     the Loader Verifier calculate the hash of the file using this algorithm
///     (typically because the caller is going to subsequently caller
///     LoaderVerifierGetHash). If the caller doesn't need a specific hash,
///     then pass in NULL.
/// </param>
/// <param name="hReserved">
///     this is a reserved handle value for future use. Caller should pass in
///     NULL.
/// </param>
/// <param name="phslauthnFile">
///     Pointer to a variable that receives a handle to the authentication
///     information for the file.
/// </param>
/// <returns>
///     If the function successfully obtained the authentication information
///     for the file, the return value is S_OK. Otherwise, error code will
///     be returned.
/// </returns>

HRESULT LoaderVerifierAuthenticateFile(
    __in        const GUID*    guidAuthClass,
    __in_opt    HANDLE         hFile,
    __in        LPCWSTR        szFilePath,
    __in_opt    LPCWSTR        szHashHint,
    __in_opt    HANDLE         hReserved,
    __out       LPHANDLE       phslauthnFile
);


/// <summary>
///     Determines which Chamber account a file should be loaded as
/// </summary>
/// <param name="hslauthnFile">
///     Handle to the authentication information (obtained by previously
///     calling LoaderVerifierAuthenticateFile).
/// </param>
/// <param name="szPreferredChamberID">
///     preferred chamber ID
/// </param>
/// <param name="psidAccount">
///     Pointer to a variable that contains the ACCTID that identifies the
///     Chamber account that the file should be loaded as.
/// </param>
/// <returns>
///     If the function successfully determined which Chamber account the file
///     should load as, the return value is S_OK. Otherwise, error code will
///     be returned.
/// </returns>
/// <remarks>
///     If a client has a priori knowledge about the account the file should
///     be loaded as, then it does not need to call this function: it can call
///     LoaderVerifierAuthorize with the appropriate account token directly.
/// </remarks>

HRESULT LoaderVerifierRouting(
    __in        HANDLE  hslauthnFile,
    __in_opt    LPCTSTR szPreferredChamberID,
    __out       ACCTID* psidAccount
);


/// <summary>
///     Determines if the calling Chamber associated with hTokenCaller 
//      can load the file into the target Chamber associated with hTokenToLoad
/// </summary>
/// <param name="hslauthnFile">
///     Handle to the authentication information (obtained by previously
///     calling LoaderVerifierAuthenticateFile).
/// </param>
/// <param name="hTokenCaller">
///     Token representing the calling Chamber that is requesting the authorization.
/// </param>
/// <param name="hTokenToLoad">
///     Token representing the Target Chamber that the file will be loaded into.
/// </param>
/// <param name="pslauthz">
///     Pointer to a variable that receives the result of the authorization
///     check. Caller must check this variable to determine whether or not
///     they should load the file when this function returns success. LoaderVerifierAuthorize's 
///     return value only indicates if the authorization process itself is successful or not.
///     If this funtion returns S_OK, and pslauthz return LV_AUTHORIZATION_DENIED,
///     the caller can call GetLastError() to determine the reason why
///     LV_AUTHORIZATION_DENIED is returned.
/// </param>
/// <returns>
///     S_OK/S_FALSE -
///            The function successfully determined the authorization result for 
///            the file. In this case, pslauthz contains the authorization result. If 
///            *plsauthz == LV_AUTHORIZATION_EXECUTE - authorization is granted. If
///            *plsauthz == LV_AUTHORIZATION_DENIED - authorization is denied. To find
///            out why authorization is denied, call GetLastError() will return one of the following 
///            values:
///                 LV_E_BLOCKED - The file is blocked by application block-list security policy.
///                 LV_E_NO_SIGNATURE - The file is not digitally signed
///                 LV_E_TAMPERED - The file has been tampered with
///                 LV_E_CERTIFICATE_EXPIRED - The signing certificate or one of the certificates in 
///                                            the trust chain is expired
///                 LV_E_CERTIFICATE_NOT_TRUSTED - The signing certificate or one of the certificates 
///                                                in the trust chain is not trusted.
///                 LV_E_CERTIFICATE_USAGE_VIOLATION - The signing certificate or one of the certificates 
///                                                    in the trust chain violated its usage constraint
///                 LV_E_NOT_CHAINED_TO_REQUIRED_CERTIFICATE - The signing certificate is not chained to 
///                                                            a specific certificate required by security policy.
///                 LV_E_CHAMBER_CAN_NOT_LAUNCH - The file is restricted from being launched by the calling chamber 
///                                               to the target chamber by security policy
///                 LV_E_RESTRICTED_TO_LAUNCH - The file has been restricted by security policy such that it 
///                                             can only be launched into one specific chamber
///                 LV_E_CERT_REVOKED - The signing certificate or one of the certificates in the trust chain 
///                                     has been revoked.
///                 HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY) - the authorization can't be granted because
///                                     of specific security policies (such as developer unlock policy, TCB hardening etc etc)
///     other HRESULT - 
///                 the authorization process itself failed.
/// </returns>
/// <remarks>
///     Here's an example to illustrate how hTokenToLoad and hTokenCaller
///     (used in LoaderVerifierAuthenticate) interact. If account A calls
///     CreateProcess(foo.exe) and foo.exe should launch as account B, then
///     hTokenCaller will be A and hTokenToLoad will be B.
/// </remarks>

HRESULT LoaderVerifierAuthorize(
    __in    HANDLE                 hslauthnFile,
    __in    HANDLE                 hTokenCaller,
    __in    HANDLE                 hTokenToLoad,
    __out   LV_AUTHORIZATION*      pslauthz
);


/// <summary>
///     Returns a hash value for the file.
/// </summary>
/// <param name="hslauthnFile">
///     Handle to the authentication information (obtained by previously
///     calling LoaderVerifierAuthenticate).
/// </param>
/// <param name="pszHashAlgorithm">
///     Specifies the CNG algorithm identifier of the hash algorithm that 
///     the caller would like to be used. If this is NULL, then the Loader  
///     Verifier will use a default algorithm. Callers who wish to retrieve 
///     hash calculated with a specific algorithm should indicate that when
///     they call LoaderVerifierAuthenticate.
/// </param>
/// <param name="pbHash">
///     Pointer to a variable that receives the hash value for the file. This
///     parameter may be NULL.
/// </param>
/// <param name="cbHash">
///     Specifies the size in bytes of the buffer that pbHash points to. This
///     parameter is ignored if pbHash is NULL.
/// </param>
/// <param name="pcbHash">
///     On exit, this parameter will contain the required size of the pbHash
///     buffer in bytes. This parameter may be NULL if pbHash is not NULL.
/// </param>
/// <param name="ppszHashAlgorithm">
///     Pointer to a CNG algorithm identifier that receives the hash algorithm 
///     used to calculate the hash. This parameter may be NULL.
///     NOTE: If this parameter is non-NULL, the algorithm identifier it points to
///     must be  freed by the caller by calling LocalFree.
/// </param>
/// <returns>
///     If the function succeeds, the return value is S_OK.
///     If hslauthFile is NULL, the return value is E_HANDLE.
///     If pszHashAlgorithm contains an invalid value, the return value is
///     E_INVALIDARG.
///     If both pbHash and pcbHash are NULL the return value is E_POINTER. 
///     If the function fails because pbHash is too small, the return value is
///     E_INSUFFICIENTBUFFER.
/// </returns>

HRESULT LoaderVerifierGetHash(
    __in                    HANDLE      hslauthnFile,
    __in_opt                LPCWSTR     pszHashAlgorithm,
    __in_bcount_opt(cbHash) BYTE*       pbHash,
    __in                    DWORD       cbHash,
    __out_opt               DWORD*      pcbHash,
    __deref_opt_out         LPWSTR*     ppszHashAlgorithm
);


/// <summary>
///     Gets a handle to the per-page hash data for the file.
/// </summary>
/// <param name="hslauthnFile">
///     Handle to the authentication information (obtained by previously
///     calling LoaderVerifierAuthenticateFile).
/// </param>
/// <param name="pbPageHashes">
///     Pointer to a variable that receives the per-page hash data. This
///     parameter may be NULL.
/// </param>
/// <param name="cbPageHashes">
///     The size in bytes of the pPageHashes memory block. This parameter is
///     ignored if pbPageHashes is NULL.
/// </param>
/// <param name="pcbPageHashes">
///     Pointer to a variable that receives the required size in bytes of the
///     pbPageHashes buffer. This parameter may be NULL.
/// </param>
/// <param name="ppszHashAlgorithm">
///     Pointer to a CNG algorithm identifier that receives the hash algorithm 
///     used to calculate the hash. This parameter may be NULL.
///     NOTE: If this parameter is non-NULL, the algorithm identifier it points to
///     must be freed by the caller by calling LocalFree.
/// </param>
/// <returns>
///     If the per-page hash data was successfully retrieved, the return value
///     is S_OK.
/// </returns>

HRESULT LoaderVerifierGetPageHashData(
    __in                            HANDLE      hslauthnFile,
    __out_ecount_opt(cbPageHashes)  BYTE*       pbPageHashes,
    __in                            DWORD       cbPageHashes,
    __out_opt                       DWORD*      pcbPageHashes,
    __deref_opt_out                 LPWSTR*     ppszHashAlgorithm
);

/// <summary>
///     Provision or re-provison a chamber assoicated with a standardlized 
///     SID. ADBNormalizeAccountName can be used to convert an AppID to a SID.
///     If the Chamber represented by szSID does not exist yet, create it first.
///
///     The fact that the szSID Chamber exisited already will be used as the 
///     indicator that the provision is a re-provision.
/// </summary>
/// <param name="szSID">
///     Unique Chamber SID to represent chamber to be created\updated.
///     The caller should call ADBNormalizeAccountName to map an AppID to a SID.
/// </param>
/// <param name="szAppFriendlyName">
///     Optional application friendly name. During re-provision and updating,
///     new friendly name will overwrite old friendly name. A new friendly name of
///     NULL means remove the friendly name (overwrite old with NULL)
///     Application name should be short, suitable for displaying on the screen.
/// </param>
/// <param name="pszCaps">
///     Pointer to dwCaps capabilities in strings.
///     For native Yamanote application, this must be NULL.
///     For managed appllication, pszCaps can potentially be NULL if that app
///     requires no extra capability other than those in Everyone group which
///     is available to all applications.
///     For re-provision, all existing capabilities will be removed first.
/// </param>
/// <param name="dwCaps">
///     Number of capabilities pointed to by pszCaps
///     for native Yamanote application, this must be 0.
/// </param>
/// <param name="szOnePEFilePath">
///     Optional path of a PE file from the application (XAP Package)
///     All binaries in a XAP package are signed with the same signing certificate
///     This API will extract the signing signature of this PE file for signing
///     certificate based authorization and routing.
///
///     Note: You can call LoaderVerifierProvisionSecurityForApplication
///           multiple times for reprovision. If the package manager decides to
///           support the case that one XAP package may contain files signed with
///           different signing ceritificates, Package Manager can do it by
///           re-provision, updating just one application.
/// </param>
/// <param name="fNativeApp">
///     if fNativeApp is TRUE, it means to provision\reprovision a SRC chamber
///     for a native Yamanote application. Otherwise, provision\reprovision a
///     LPC chamber for a managed or hybrid application.
/// </param>
/// <returns>
///     S_OK. - If the function succeeds
///     appropriate error - if provisioning or re-provisioning fails
///       Common error code include:
///         HRESULT_FROM_WIN32(ERROR_BAD_ARGUMENTS): when
///                 - dwCaps is nonzero for Native Application
///                 - dwCaps is nonzero and pszCaps is NULL
///         HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED):
///                 - any of the capabilities in pszCaps is private
/// </returns>
/// <remarks>
///     (1) The existence of the szSID chamber will be used as an indicator
///         that the provision is a re-provision
///     (2) Re-provision always removes current provisioned capabilities first.
///         however, old signing certificate extracted from the PE File in 
///         szOnePEFilePath will not be removed. This will make reprovison
///         easier and allows that updated/new files be signed with different
///         signing  certificate.
///     (3) It is the Application Platform that should manage the fNativeApp
///         state of an XAP package, not Secure Loader
///     (4) This API can be called by TCB only.
///     (5) If any capabilities passed is not available on the device, the API
///         will fail and return error code ERROR_NO_SUCH_USER.
/// </remarks>
HRESULT
LoaderVerifierProvisionSecurityForApplication(
    __in                LPCWSTR     szSID,
    __in_z_opt          LPCWSTR     szAppFriendlyName,
    __in_ecount_opt(dwCaps) LPCWSTR*    pszCaps,
    __in                DWORD       dwCaps,
    __in_z_opt          LPCWSTR     szOnePEFilePath,
    __in                BOOL        fNativeApp
);

/// <summary>
///     Delete chamber associated with the AppID and remove all the rules
///     associated with it from policy rule data base
/// </summary>
/// <param name="szSID">
///     Unique Chamber SID to represent the chamber to be removed. The caller should
///     call ADBNormalizeAccountName to map an AppID to a SID.
/// </param>
/// <returns>
///     S_OK. - If the function succeeds
///     appropriate error - if deprovisioning fails
///     Common error code include:
/// </returns>
/// <remarks>
///     This API can be called by TCB only and it is currently not fast (O(N))
///     It opens each policy rule in database, checks rule's
///     CE_POLICY_DATA_TYPE_AUTHORIZATION and CE_POLICY_DATA_TYPE_STOP lists:
///     - deletes the rule if it only contains information related to szSID, or
///     - recreates the rule if it contains information related to szSID and
///                 other accounts by removing information related to szSID, or
///     - ignores it if it doesn't contain information related to szSID
/// </remarks>
HRESULT
LoaderVerifierDeprovisionSecurityForApplication(
    __in LPCWSTR szSID
);

/// <summary>
///     Make a CA certificate be a trusted TCB CA certificate at runtime
/// </summary>
/// <param name="szThumbprint">
///     The thumbprint of the certificate to be trusted
/// </param>
/// <returns>
///     S_OK/S_FALSE - If the function succeeded
///     others - failed
/// </returns>
/// <remarks>
///         (1) only TCB application is able to make this call
///         (2) It's the TCB application's responsibilty to do other means of
///             authentication before calling this method. Anyone uses this API
///             must contact the security team first.
/// </remarks>
HRESULT
LoaderVerifierAuthorizeVolatileCertificate(__in_z LPCWSTR szThumbprint );



#ifdef WINCEMACRO
#include <mloaderverifier.h>
#endif

#ifdef __cplusplus
}
#endif // __cplusplus
    
#endif // _LOADERVERIFIER_H_

