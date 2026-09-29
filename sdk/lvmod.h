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
// This file documents the DLL entry points exposed by a file verification
// module. These functions are used by the implementation of the LVMod
// APIs (see LVMod.h). 
//
// Each function entry specifies:
// -- function prototype exported by the loader verification module dll
// -- typedef to be used when getting the function entry point from dll
// -- name of the function to be used when getting function entry point
//

#ifndef _LVMOD_H_
#define _LVMOD_H_

#if (_MSC_VER >= 1000)
#pragma once
#endif

#include "windows.h"
#include <wincrypt.h> // for ALG_ID definition

DECLARE_HANDLE(HLVMODAUTHENTICATIONDATA);

#include "adb7.h"

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus


/// <summary>
///     Initializes the verification module. 
/// </summary>
/// <returns>
///     Returns S_OK if the module initializes successfully. 
/// </returns>
/// <remarks>
///     This function will be called by the kernel to initialize the verifier
///     module. 
/// </remarks>

HRESULT LVModInitialize (void);
typedef HRESULT (*PFNLVModInitialize) (void);
#define LVMOD_INITIALIZE "LVModInitialize"

    
/// <summary>
///     Uninitializes the verification module, in preparation to unload it. 
/// </summary>    
/// <returns>
///     Returns S_OK if the module uninitialized successfully. 
/// </returns>
    
HRESULT LVModUninitialize (void);
typedef HRESULT (*PFNLVModUninitialize) (void);    
#define LVMOD_UNINITIALIZE "LVModUninitialize"


/// <summary>
///     Obtains authentication information for a file. 
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
///     LVModGetHash). If the caller doesn't need a specific hash,
///     then pass in NULL.
/// </param>
/// <param name="hauthnCatalog">
///     Handle to the authentication information returned for the
///     catalog file that references the file being authenticated. For
///     example, the installer would pass in the authentication handle for the
///     CAB file when verifying the files within the CAB. If there's no
///     catalog file associated with the file, then this parameter should be
///     NULL. 
/// </param>
/// <param name="phslauthnFile">
///     Pointer to a variable that receives a handle to the authentication
///     information for the file. 
/// </param>
/// <returns>
///     If the function successfully obtained the authentication information 
///     for the file, the return value is S_OK. 
/// </returns>

HRESULT LVModAuthenticateFile(
    __in     const GUID*                guidAuthClass,
    __in_opt HANDLE                     hFile,
    __in     LPCWSTR                    szFilePath,
    __in_opt LPCWSTR                    szHashHint,
    __in_opt HANDLE                     hauthnCatalog,
    __out    HLVMODAUTHENTICATIONDATA*  phlvauthnFile
);
typedef HRESULT (*PFNLVModAuthenticateFile) (
    const GUID*,
    HANDLE,
    LPCWSTR,
    LPCWSTR,
    HANDLE,
    HLVMODAUTHENTICATIONDATA*
);
#define LVMOD_AUTHENTICATE_FILE "LVModAuthenticateFile"


/// <summary>
///     Determines which principal (chamber) a file should be loaded as.
/// </summary>
/// <param name="hslauthnFile">
///     Handle to the authentication information (obtained by previously 
///     calling LVModAuthenticateFile).
/// </param>
/// <param name="szPreferredChamberID">
///     the preferred chamber ID
/// </param>
/// <param name="psidAccount">
///     Pointer to a variable that contains the SID that identifies the
///     account that the file should be loaded as.
/// </param>
/// <returns>
///     If the function successfully determined which principal the file
///    should load as, the return value is S_OK. 
/// </returns>
/// <remarks>
///     If a client has a priori knowledge about the account the file should
///     be loaded as, then it does not need to call this function: it can call
///     LVModAuthorize with the appropriate account token directly. 
/// </remarks>

HRESULT LVModRouting(
    __in        HLVMODAUTHENTICATIONDATA   hlvauthnFile,
    __in_opt    LPCTSTR                    szPreferredChamberID,
    __out       PACCTID                    psidAccount
);
typedef HRESULT (*PFNLVModRouting) (
    HLVMODAUTHENTICATIONDATA,
    LPCTSTR,
    PACCTID
);
#define LVMOD_ROUTING "LVModRouting"


/// <summary>
///     Determines if the calling Chamber associated with hTokenCaller 
//      can load the file into the target Chamber associated with hTokenToLoad
/// </summary>
/// <param name="hslauthnFile">
///     Handle to the authentication information (obtained by previously
///     calling LVModAuthenticateFile).
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
///     they should load the file when this function returns success. LVModAuthorize's 
///     return value only indicates if the authorization process itself is successful or not.
///     If this funtion returns S_OK, and pslauthz return LV_AUTHORIZATION_DENIED,
///     the caller can call GetLastError() to determine the reason why
///     LV_AUTHORIZATION_DENIED is returned.
/// </param>
/// <returns>
///     S_OK/S_FALSE -
///            The function successfully determined the authorization result for 
///            the file. In this case, pslauthz contains the authorization result. If 
///            *plvauthz == LV_AUTHORIZATION_EXECUTE - authorization is granted. If
///            *plvauthz == LV_AUTHORIZATION_DENIED - authorization is denied. To find
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
///     (used in LVModAuthenticate) interact. If account A calls
///     CreateProcess(foo.exe) and foo.exe should launch as account B, then
///     hTokenCaller will be A and hTokenToLoad will be B.
/// </remarks>
HRESULT LVModAuthorize(
    __in HLVMODAUTHENTICATIONDATA   hlvauthnFile,
    __in HANDLE                     hTokenCaller,
    __in HANDLE                     hTokenToLoad,
    __out enum LV_AUTHORIZATION*    plvauthz
);
typedef HRESULT (*PFNLVModAuthorize) (
    HLVMODAUTHENTICATIONDATA,
    HANDLE,
    HANDLE,
    enum LV_AUTHORIZATION*
);
#define LVMOD_AUTHORIZE "LVModAuthorize"


/// <summary>
///     Gets a handle to the per-page hash data for the file.
/// </summary>
/// <param name="hslauthnFile">
///     Handle to the authentication information (obtained by previously 
///     calling LVModAuthenticate).
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

HRESULT LVModGetPageHashData(
    __in                            HLVMODAUTHENTICATIONDATA    hlvauthnFile,
    __out_ecount_opt(cbPageHashes)  LPBYTE                      pbPageHashes,
                                    DWORD                       cbPageHashes,
    __out_opt                       LPDWORD                     pcbPageHashes,
    __deref_opt_out                 LPWSTR*     ppszHashAlgorithm
);
typedef HRESULT (*PFNLVModGetPageHashData)(
    HLVMODAUTHENTICATIONDATA,
    LPBYTE,
    DWORD,
    LPDWORD,
    LPWSTR*
);
#define LVMOD_GET_PAGE_HASH_DATA "LVModGetPageHashData"


/// <summary>
///     Closes an authentication handle obtained by a call to
///     LVModAuthenticateFile. 
/// </summary>
/// <param name="hslauthnFile">
///     Handle to the authentication information.
/// </param>

void LVModCloseAuthenticationHandle(
    __in HLVMODAUTHENTICATIONDATA hlvauthnFile
);
typedef void (*PFNLVModCloseAuthenticationHandle) (
    HLVMODAUTHENTICATIONDATA
);
#define LVMOD_CLOSE_AUTHENTICATION_HANDLE "LVModCloseAuthenticationHandle"


/// <summary>
///     Returns a hash value for the file.
/// </summary>
/// <param name="hslauthnFile">
///     Handle to the authentication information (obtained by previously 
///     calling LVModAuthenticateFile).
/// </param>
/// </param>
/// <param name="pszHashAlgorithm">
///     Specifies the CNG algorithm identifier of the hash algorithm that 
///     the caller would like to be used. If this is NULL, then the Loader  
///     Verifier will use a default algorithm. Callers who wish to retrieve 
///     hash calculated with a specific algorithm should indicate that when
///     they call LVModAuthenticate.
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
///     must be freed by the caller by calling LocalFree.
/// </param>
/// <returns>
///     If the function succeeds, the return value is S_OK.
///     If hslauthFile is NULL, the return value is E_HANDLE.
///     If aiHashAlgorithm contains an invalid value, the return value is
///     E_INVALIDARG.
///     If both pbHash and pcbHash are NULL the return value is E_POINTER.
///     If the function fails because pbHash is too small, the return value is
///     E_INSUFFICIENTBUFFER. 
/// </returns>

HRESULT LVModGetHash(
    __in                    HLVMODAUTHENTICATIONDATA    hlvauthnFile,
    __in                    LPCWSTR                     pszHashAlgorithm,
    __in_bcount_opt(cbHash) LPBYTE                      pbHash,
                            DWORD                       cbHash,
    __out_opt               LPDWORD                     pcbHash,
    __deref_opt_out         LPWSTR*                     ppszHashAlgorithm
);
typedef HRESULT (*PFNLVModGetHash) (
    HLVMODAUTHENTICATIONDATA,
    LPCWSTR,
    LPBYTE,
    DWORD,
    LPDWORD,
    LPWSTR*
);
#define LVMOD_GET_HASH "LVModGetHash"

/// <summary>
///     Get PE/XAP file's signing certificate's thumbprint and hash algorithm
/// </summary>
/// <param name="hlvauthnFile">
///     Handle returned from LVModVerifierAuthenticateFile
/// </param>
/// <param name="pbHash">
///     Input buffer used to retrive the thumb print of the signing certificate
///     Its size is cbHash. If pbHash is NULL,calling this function with non-NULL pcbHash,
///     pcbHash can return required size for pbHash
/// </param>
/// <param name="cbHash">
///     Buffer size of pbHash in bytes. If pbHash is NULL, cbHash needs to be zero.
/// </param>
/// <param name="pcbHash">
///     Actually bytes returned in pbHash. It should be true that *pcbHash <= cbHash
/// </param>
/// <param name="ppszHashAlgorithm">
///     Pointer to a CNG algorithm identifier that receives the hash algorithm 
///     used to calculate the thumb print. This parameter may be NULL.
///     NOTE: If this parameter is non-NULL, the algorithm identifier it points to
///     must be  freed by the caller by calling LocalFree
/// </param>
/// <returns>
///     S_OK - if successful
///      E_INVALIDARG - input arguments are not valid
///     LV_E_NO_SIGNATURE - no signing signature found
///     E_OUTOFMEMORY - out of memory
///     HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) - input buffer for pbHash is too small
///     other - failed
/// </returns>

HRESULT LVModGetSignerCertificateThumbprint(    __in                    HLVMODAUTHENTICATIONDATA  hlvauthnFile,
                                                __in_bcount_opt(cbHash) LPBYTE                    pbHash,
                                                __in                    DWORD                     cbHash,
                                                __out_opt               LPDWORD                   pcbHash,
                                                __deref_opt_out         LPWSTR*                   ppszHashAlgorithm);

typedef HRESULT (*PFNLVModGetSignerCertificateThumbprint) (
    HLVMODAUTHENTICATIONDATA,
    LPBYTE,
    DWORD,
    LPDWORD,
    LPWSTR*
);
#define LVMOD_GETSIGNERCERTIFICATETHUMBPRINT "LVModGetSignerCertificateThumbprint"

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
///     Note: You can call LVModProvisionSecurityForApplication
///           multiple times for reprovision. If the package manager decides to
///           support the case that one XAP package may contain files signed with
///           different signing ceritificates, Package Manager can do it by
///           re-provision, updating just one application.
/// </param>
/// <param name="fNativeApp">
///     if fNativeApp is TRUE, it means to provision\reprovision a SRC chamber
///     for a native Yamanote application. Otherwise, provision\reprovision a
///     LPC chamber for a managed application or Hybrid application.
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
LVModProvisionSecurityForApplication(
    __in                LPCWSTR     szSID,
    __in_z_opt          LPCWSTR     szAppFriendlyName,
    __in_ecount_opt(dwCaps) LPCWSTR*    pszCaps,
    __in                DWORD       dwCaps,
    __in_z_opt          LPCWSTR     szOnePEFilePath,
    __in                BOOL        fNativeApp
);
typedef HRESULT (*PFNLVModProvisionSecurityForApplication) (
    LPCWSTR,
    LPCWSTR,
    LPCWSTR*,
    DWORD,
    LPCWSTR,
    BOOL
);
#define LVMOD_PROVISION_SECURITY_FOR_APPLICATION "LVModProvisionSecurityForApplication"

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
LVModDeprovisionSecurityForApplication(
    __in                LPCWSTR     szSID
);
typedef HRESULT (*PFNLVModDeprovisionSecurityForApplication) (
    LPCWSTR
);
#define LVMOD_DEPROVISION_SECURITY_FOR_APPLICATION "LVModDeprovisionSecurityForApplication"

/// <summary>
///     Make a CA certificate be a trusted TCB CA certificate at runtime
/// </summary>
/// <param name="szThumbprint">
///     The thumbprint of the certificate to be trusted
/// </param>
/// <returns>
///     S_OK. - If the function succeeds
///     others - failed
/// </returns>
/// <remarks>
///         (1) only TCB application is able to make this call
///         (2) It's the TCB application's responsibilty to do other means of
///             authentication before calling this method. Anyone uses this API
///             must contact the security team first.
/// </remarks>
HRESULT
LVModAuthorizeVolatileCertificate(__in_z LPCWSTR szThumbprint );

typedef HRESULT (*PFNLVModAuthorizeVolatileCertificate) ( __in_z LPCWSTR szThumbprint);
#define LVMOD_AUTHORIZEVOLATILECERTIFICATE  "LVModAuthorizeVolatileCertificate"





/// <summary>
///     Get current DeveloperUnlock enabling State
/// </summary>
/// <param name="pelvDeveloperUnlockState">
///     Pointer to LV_DEVELOPERUNLOCKSTATE variable receiving current developer unlock
///   enabling state.
/// </param>
/// <returns>
///     S_OK/S_FALSE - If the function succeeds
///     appropriate error - otherwise
/// </returns>
HRESULT
LVModGetDeveloperUnlockState(
    __out              enum LV_DEVELOPERUNLOCKSTATE* pelvDeveloperUnlockState
);

typedef HRESULT (*PFNLVModGetDeveloperUnlockState) (
    enum LV_DEVELOPERUNLOCKSTATE*
);

#define LVMOD_GET_DEVELOPERUNLOCKSTATE "LVModGetDeveloperUnlockState"

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
LVModSetDeveloperUnlockState(
    enum LV_DEVELOPERUNLOCKSTATE elvDeveloperUnlockState
);
typedef HRESULT (*PFNLVModSetDeveloperUnlockState) (
    enum LV_DEVELOPERUNLOCKSTATE
);
#define LVMOD_SET_DEVELOPERUNLOCKSTATE "LVModSetDeveloperUnlockState"


#ifdef __cplusplus
}
#endif // __cplusplus
    
#endif // _LVMOD_H_

