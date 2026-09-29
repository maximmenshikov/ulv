/* FullUnlock v4.0 project.
   LoaderVerifier implementation.
   
   (C) ultrashot 2012
*/
#include "stdafx.h"
#include "adb7.h"

extern "C"
{
    HRESULT CeGetProcessAccount(HANDLE hProcess, PACCTID accountId,
                                DWORD cbSize);
}

/**
 * Return the owner account of a process.
 *
 * @param hProcess    Process handle.
 *
 * @return The owner account id.
 */
ACCTID
GetAccount(HANDLE hProcess)
{
    ACCTID account;
    CeGetProcessAccount(hProcess, &account, sizeof(ACCTID));
    return account;
}

/**
 * Resolve the SID name of an account id.
 *
 * @param accountID              Account id to resolve.
 * @param lpwszAccountName       Output buffer for the name.
 * @param dwAccountNameLength    Size of the output buffer, in characters.
 *
 * @return TRUE on success, FALSE otherwise.
 */
BOOL
GetAccountName(ACCTID accountID, LPWSTR lpwszAccountName,
               DWORD dwAccountNameLength)
{
    DWORD strSize = dwAccountNameLength;
    ACCTID account = accountID;
    if (ADBNameFromAccountID(&account, lpwszAccountName, &strSize) ==
        ERROR_SUCCESS)
        return TRUE;
    return FALSE;
}

/**
 * Resolve and normalize the SID name of an account id.
 *
 * @param accountID              Account id to resolve.
 * @param lpwszAccountName       Output buffer for the normalized name.
 * @param dwAccountNameLength    Size of the output buffer, in characters.
 *
 * @return FALSE (the normalized name is written to @p lpwszAccountName).
 */
BOOL
GetNormalizedAccountName(ACCTID accountID, LPWSTR lpwszAccountName,
                         DWORD dwAccountNameLength)
{
    ACCTID account = accountID;

    wchar_t name[500];
    DWORD nameLength = 500;
    if (GetAccountName(account, name, nameLength) == TRUE)
    {
        DWORD strSize = dwAccountNameLength;
        ADBNormalizeAccountName(name, lpwszAccountName, &strSize);
    }
    return FALSE;
}

/**
 * Resolve an account id from a SID name.
 *
 * @param lpwszAccountName    Account SID string.
 *
 * @return The account id, or 0 if it cannot be resolved.
 */
ACCTID
Name2AccountID(LPWSTR lpwszAccountName)
{
    ACCTID account = 0;
    ADBAccountIDFromName(lpwszAccountName, &account);
    return account;
}
