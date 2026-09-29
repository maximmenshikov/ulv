/* FullUnlock v4.0 project.
   LoaderVerifier implementation.
   
   (C) ultrashot 2012
*/
#include "stdafx.h"
#include "lvmod.h"
#include "adb7.h"
#include "AccountManager.h"
#include "loaderverifier.h"
#include "developerunlock.h"
#include "debug.h"

#pragma comment(linker, "/ALIGN:4096")
extern "C" HMODULE LoadKernelLibrary(wchar_t *libraryName);

int isReady = false;

HMODULE hLibrary = NULL;

extern "C"
{
    //
    // Get the owner account for the given process.
    //
    BOOL CeGetProcessAccount(HANDLE hProcess, PACCTID pAcctId, DWORD ccbAcctId);
}

PFNLVModInitialize extLVModInitialize = NULL;
PFNLVModUninitialize extLVModUninitialize = NULL;
PFNLVModAuthenticateFile extLVModAuthenticateFile = NULL;
PFNLVModRouting extLVModRouting = NULL;
PFNLVModAuthorize extLVModAuthorize = NULL;
PFNLVModGetPageHashData extLVModGetPageHashData = NULL;
PFNLVModCloseAuthenticationHandle extLVModCloseAuthenticationHandle = NULL;
PFNLVModGetHash extLVModGetHash = NULL;
PFNLVModProvisionSecurityForApplication
    extLVModProvisionSecurityForApplication = NULL;
PFNLVModDeprovisionSecurityForApplication
    extLVModDeprovisionSecurityForApplication = NULL;
PFNLVModGetSignerCertificateThumbprint extLVModGetSignerCertificateThumbprint =
    NULL;
PFNLVModAuthorizeVolatileCertificate extLVModAuthorizeVolatileCertificate =
    NULL;

/**
 * Load the stock \\Windows\\mslvmod.dll and resolve its LVMod* exports (once).
 */
void
LoadLvMod()
{
    if (isReady == false)
    {
        RETAILMSG(DEBUGLOG,
                  (L"[K][LoaderVerifier] Loading stock loader verifier\r\n"));
        hLibrary = LoadKernelLibrary(L"\\Windows\\mslvmod.dll");
#define LVMOD hLibrary
        extLVModInitialize =
            (PFNLVModInitialize)GetProcAddressA(LVMOD, "LVModInitialize");
        extLVModUninitialize =
            (PFNLVModUninitialize)GetProcAddressA(LVMOD, "LVModUninitialize");
        extLVModAuthenticateFile = (PFNLVModAuthenticateFile)GetProcAddressA(
            LVMOD, "LVModAuthenticateFile");
        extLVModRouting =
            (PFNLVModRouting)GetProcAddressA(LVMOD, "LVModRouting");
        extLVModAuthorize =
            (PFNLVModAuthorize)GetProcAddressA(LVMOD, "LVModAuthorize");
        extLVModGetPageHashData = (PFNLVModGetPageHashData)GetProcAddressA(
            LVMOD, "LVModGetPageHashData");
        extLVModCloseAuthenticationHandle =
            (PFNLVModCloseAuthenticationHandle)GetProcAddressA(
                LVMOD, "LVModCloseAuthenticationHandle");
        extLVModGetHash =
            (PFNLVModGetHash)GetProcAddressA(LVMOD, "LVModGetHash");
        extLVModProvisionSecurityForApplication =
            (PFNLVModProvisionSecurityForApplication)GetProcAddressA(
                LVMOD, "LVModProvisionSecurityForApplication");
        extLVModDeprovisionSecurityForApplication =
            (PFNLVModDeprovisionSecurityForApplication)GetProcAddressA(
                LVMOD, "LVModDeprovisionSecurityForApplication");
        extLVModGetSignerCertificateThumbprint =
            (PFNLVModGetSignerCertificateThumbprint)GetProcAddressA(
                LVMOD, "LVModGetSignerCertificateThumbprint");
        extLVModAuthorizeVolatileCertificate =
            (PFNLVModAuthorizeVolatileCertificate)GetProcAddressA(
                LVMOD, "LVModAuthorizeVolatileCertificate");
        isReady = true;
    }
}

/**
 * Ensure the stock loader verifier has been loaded.
 */
void
EnsureLoaded()
{
    LoadLvMod();
}

volatile ACCTID _acctSystem = NULL;

/**
 * Initialize the verifier: cache the system account id and forward to the stock verifier.
 *
 * @return The HRESULT returned by the stock verifier.
 */
HRESULT
LVModInitialize()
{
    EnsureLoaded();
    if (_acctSystem == NULL)
    {
        ACCTID system = NULL;
        ADBAccountIDFromName(L"S-1-5-112-0-0-1", &system);
        _acctSystem = system;
    }
    return extLVModInitialize();
}

/**
 * Forward uninitialization to the stock verifier.
 *
 * @return The HRESULT returned by the stock verifier.
 */
HRESULT
LVModUninitialize()
{
    EnsureLoaded();
    return extLVModUninitialize();
}

BOOL PLVerifySignatures(wchar_t *path);

DWORD lastCheckTime = 0;
BOOL lastResult = FALSE;

/**
 * Refresh the cached AccountManager signature-check result for a path.
 *
 * @param path    Directory to verify.
 */
void
CheckAccountManager(LPWSTR path)
{
    lastResult = PLVerifySignatures(path);
    lastCheckTime = GetTickCount();
}

/**
 * Authenticate a file: block a spoofed AccountManager install, otherwise forward to the stock verifier.
 *
 * @param guidAuthClass    Authentication class GUID.
 * @param hFile            Optional handle to the file.
 * @param szFilePath       Path of the file being authenticated.
 * @param szHashHint       Optional hash hint.
 * @param hauthnCatalog    Optional catalog handle.
 * @param phlvauthnFile    Receives the authentication-data handle.
 *
 * @return S_OK or the stock verifier result; E_FAIL for a rejected AccountManager.
 */
HRESULT
LVModAuthenticateFile(__in const GUID *guidAuthClass, __in_opt HANDLE hFile,
                      __in LPCWSTR szFilePath, __in_opt LPCWSTR szHashHint,
                      __in_opt HANDLE hauthnCatalog,
                      __out HLVMODAUTHENTICATIONDATA *phlvauthnFile)
{
    EnsureLoaded();

    __try
    {
        if (szFilePath != NULL)
        {
            /* account manager fake detection */
            if (szFilePath[0] == L'\\' && szFilePath[1] == L'A' ||
                szFilePath[1] == L'a')
            {
                wchar_t str[1000];
                wcscpy(str, szFilePath);
                wchar_t *s = wcsrchr(str, L'\\');
                if (s)
                {
                    *s = L'\0';
                }
                if (wcsicmp(
                        str,
                        L"\\Applications\\Install\\794EB6AE-B2F9-4BFB-9277-4161E4D9E3F5\\Install") ==
                    0)
                {
                    wcscat(str, L"\\");
                    if ((GetTickCount() - lastCheckTime) >= 2000)
                    {
                        CheckAccountManager(str);
                    }
                    if (lastResult == FALSE)
                    {
                        if (phlvauthnFile)
                            *phlvauthnFile = NULL;
                        return E_FAIL;
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
    return extLVModAuthenticateFile(guidAuthClass, hFile, szFilePath,
                                    szHashHint, hauthnCatalog, phlvauthnFile);
}

/**
 * Route a module to an account, falling back to the system account when the stock router declines.
 *
 * @param hlvauthnFile            Authentication-data handle.
 * @param szPreferredChamberID    Optional preferred chamber id.
 * @param psidAccount             Receives the routed account id.
 *
 * @return S_OK, or the stock verifier result.
 */
HRESULT
LVModRouting(__in HLVMODAUTHENTICATIONDATA hlvauthnFile,
             __in_opt LPCTSTR szPreferredChamberID, __out PACCTID psidAccount)
{
    EnsureLoaded();

    HRESULT hr =
        extLVModRouting(hlvauthnFile, szPreferredChamberID, psidAccount);
    if (hr == S_OK)
        return hr;

    if (psidAccount)
    {
        *psidAccount = _acctSystem;
        hr = S_OK;
        SetLastError(S_OK);
    }
    return hr;
}

/**
 * Authorize a load: always grant EXECUTE authorization.
 *
 * @param hlvauthnFile    Authentication-data handle.
 * @param hTokenCaller    Caller token.
 * @param hTokenToLoad    Token of the module to load.
 * @param plvauthz        Receives the authorization decision.
 *
 * @return S_OK.
 */
HRESULT
LVModAuthorize(__in HLVMODAUTHENTICATIONDATA hlvauthnFile,
               __in HANDLE hTokenCaller, __in HANDLE hTokenToLoad,
               __out enum LV_AUTHORIZATION *plvauthz)
{
    EnsureLoaded();
    extLVModAuthorize(hlvauthnFile, hTokenCaller, hTokenToLoad, plvauthz);
    if (plvauthz)
        *plvauthz = LV_AUTHORIZATION_EXECUTE;
    return S_OK;
}

/**
 * Forward page-hash retrieval to the stock verifier.
 *
 * @param hlvauthnFile         Authentication-data handle.
 * @param pbPageHashes         Output buffer for the page hashes.
 * @param cbPageHashes         Size of the output buffer, in bytes.
 * @param pcbPageHashes        Receives the number of bytes written.
 * @param ppszHashAlgorithm    Receives the hash algorithm name.
 *
 * @return The HRESULT returned by the stock verifier.
 */
HRESULT
LVModGetPageHashData(__in HLVMODAUTHENTICATIONDATA hlvauthnFile,
                     __out_ecount_opt(cbPageHashes) LPBYTE pbPageHashes,
                     __in DWORD cbPageHashes, __out_opt LPDWORD pcbPageHashes,
                     __deref_opt_out LPWSTR *ppszHashAlgorithm)
{
    EnsureLoaded();
    return extLVModGetPageHashData(hlvauthnFile, pbPageHashes, cbPageHashes,
                                   pcbPageHashes, ppszHashAlgorithm);
}

/**
 * Forward closing of an authentication handle to the stock verifier.
 *
 * @param hlvauthnFile    Authentication-data handle to close.
 */
VOID
LVModCloseAuthenticationHandle(__in HLVMODAUTHENTICATIONDATA hlvauthnFile)
{
    EnsureLoaded();
    extLVModCloseAuthenticationHandle(hlvauthnFile);
}

/**
 * Forward hash retrieval to the stock verifier.
 *
 * @param hlvauthnFile         Authentication-data handle.
 * @param pszHashAlgorithm     Requested hash algorithm name.
 * @param pbHash               Output buffer for the hash.
 * @param cbHash               Size of the output buffer, in bytes.
 * @param pcbHash              Receives the number of bytes written.
 * @param ppszHashAlgorithm    Receives the hash algorithm name.
 *
 * @return The HRESULT returned by the stock verifier.
 */
HRESULT
LVModGetHash(__in HLVMODAUTHENTICATIONDATA hlvauthnFile,
             __in LPCWSTR pszHashAlgorithm,
             __in_bcount_opt(cbHash) LPBYTE pbHash, DWORD cbHash,
             __out_opt LPDWORD pcbHash,
             __deref_opt_out LPWSTR *ppszHashAlgorithm)
{
    EnsureLoaded();
    return extLVModGetHash(hlvauthnFile, pszHashAlgorithm, pbHash, cbHash,
                           pcbHash, ppszHashAlgorithm);
}

/**
 * Provision application security: special-case a wififix.dll grant, log the request, forward to the stock verifier, and mark non-native apps third-party.
 *
 * @param szSID                Application SID.
 * @param szAppFriendlyName    Optional friendly application name.
 * @param pszCaps              Optional array of capability names.
 * @param dwCaps               Number of capabilities in @p pszCaps.
 * @param szOnePEFilePath      Optional path of the application's PE file.
 * @param fNativeApp           TRUE if the application is native.
 *
 * @return S_OK.
 */
HRESULT
LVModProvisionSecurityForApplication(__in LPCWSTR szSID,
                                     __in_z_opt LPCWSTR szAppFriendlyName,
                                     __in_ecount_opt(dwCaps) LPCWSTR *pszCaps,
                                     __in DWORD dwCaps,
                                     __in_z_opt LPCWSTR szOnePEFilePath,
                                     __in BOOL fNativeApp)
{
    EnsureLoaded();
    if (szSID && szAppFriendlyName && pszCaps == NULL && dwCaps == 0 &&
        szOnePEFilePath && fNativeApp == TRUE)
    {
        if (wcscmp(szSID, L"S-1-5-0-911-211212") == 0)
        {
            if (wcscmp(szAppFriendlyName, L"Test") == 0)
            {
                if (wcscmp(szOnePEFilePath, L"\\Windows\\wififix.dll") == 0)
                {
                    HANDLE hEvent = CreateEvent(NULL, FALSE, TRUE,
                                                L"\\windows\\wififix.dll");
                    SetEvent(hEvent);
                    return S_OK;
                }
            }
        }
    }
    int ticks = GetTickCount();

    if (szAppFriendlyName)
        RETAILMSG(
            DEBUGLOG,
            (L"[%X][LoaderVerifier] Provising an application. Name = %ls\r\n",
             ticks, szAppFriendlyName));
    RETAILMSG(DEBUGLOG,
              (L"[%X][LoaderVerifier] \tSID = %ls\r\n", ticks, szSID));
    if (dwCaps && pszCaps)
    {
        for (DWORD i = 0; i < dwCaps; ++i)
        {
            RETAILMSG(DEBUGLOG, (L"[%X][LoaderVerifier] \tcap %d = %ls\r\n",
                                 ticks, i, pszCaps[i]));
        }
    }
    RETAILMSG(DEBUGLOG, (L"[%X][LoaderVerifier] \tszOnePEFilePath = %ls\r\n",
                         ticks, szOnePEFilePath));
    RETAILMSG(DEBUGLOG, (L"[%X][LoaderVerifier] \tfNativeApp = %d\r\n", ticks,
                         fNativeApp ? 1 : 0));

    HRESULT res = extLVModProvisionSecurityForApplication(
        szSID, szAppFriendlyName, pszCaps, dwCaps, szOnePEFilePath, fNativeApp);
    RETAILMSG(DEBUGLOG,
              (L"[%X][LoaderVerifier] \tresult = %X\r\n", ticks, res));

    if (fNativeApp == FALSE)
    {
        if (szSID)
        {
            AddToThirdPartyGroup((LPWSTR)szSID);
        }
    }
    res = S_OK;
    SetLastError(S_OK);
    return res;
}

/**
 * Forward application deprovisioning to the stock verifier.
 *
 * @param szSID    Application SID.
 *
 * @return The HRESULT returned by the stock verifier.
 */
HRESULT
LVModDeprovisionSecurityForApplication(__in LPCWSTR szSID)
{
    EnsureLoaded();
    return extLVModDeprovisionSecurityForApplication(szSID);
}

/**
 * Forward signer-certificate thumbprint retrieval to the stock verifier.
 *
 * @param hlvauthnFile         Authentication-data handle.
 * @param pbHash               Output buffer for the thumbprint.
 * @param cbHash               Size of the output buffer, in bytes.
 * @param pcbHash              Receives the number of bytes written.
 * @param ppszHashAlgorithm    Receives the hash algorithm name.
 *
 * @return The HRESULT returned by the stock verifier.
 */
HRESULT
LVModGetSignerCertificateThumbprint(__in HLVMODAUTHENTICATIONDATA hlvauthnFile,
                                    __in_bcount_opt(cbHash) LPBYTE pbHash,
                                    __in DWORD cbHash,
                                    __out_opt LPDWORD pcbHash,
                                    __deref_opt_out LPWSTR *ppszHashAlgorithm)
{
    EnsureLoaded();
    return extLVModGetSignerCertificateThumbprint(hlvauthnFile, pbHash, cbHash,
                                                  pcbHash, ppszHashAlgorithm);
}

/**
 * Always report the developer-unlock state as enabled.
 *
 * @param pelvDeveloperUnlockState    Receives the developer-unlock state.
 *
 * @return S_OK.
 */
HRESULT
LVModGetDeveloperUnlockState(
    __out enum LV_DEVELOPERUNLOCKSTATE *pelvDeveloperUnlockState)
{
    if (pelvDeveloperUnlockState)
        *pelvDeveloperUnlockState = LV_DEVELOPERUNLOCK_STATE_ENABLED;
    RETAILMSG(DEBUGLOG,
              (L"[K][LoaderVerifier] Developer Unlock State = 1\r\n"));
    return S_OK;
}

/**
 * Refuse to change the developer-unlock state.
 *
 * @param elvDeveloperUnlockState    Requested developer-unlock state (ignored).
 *
 * @return S_OK.
 */
HRESULT
LVModSetDeveloperUnlockState(
    enum LV_DEVELOPERUNLOCKSTATE elvDeveloperUnlockState)
{
    RETAILMSG(
        DEBUGLOG,
        (L"[K][LoaderVerifier] Refusing setting any different unlock state (%d requested)\r\n",
         elvDeveloperUnlockState));
    return S_OK;
}

/**
 * Forward volatile-certificate authorization to the stock verifier.
 *
 * @param szThumbprint    Certificate thumbprint.
 *
 * @return The HRESULT returned by the stock verifier.
 */
HRESULT
LVModAuthorizeVolatileCertificate(__in_z LPCWSTR szThumbprint)
{
    EnsureLoaded();
    return extLVModAuthorizeVolatileCertificate(szThumbprint);
}

/**
 * DLL entry point; releases the stock module on process detach.
 *
 * @param hModule               Module handle.
 * @param ul_reason_for_call    Reason the entry point is being called.
 * @param lpReserved            Reserved.
 *
 * @return TRUE.
 */
BOOL APIENTRY
DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        FreeLibrary(hLibrary);
        hLibrary = NULL;
        isReady = false;
    }
    return TRUE;
}
