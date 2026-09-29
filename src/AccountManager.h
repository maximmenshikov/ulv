/* FullUnlock v4.0 project.
   LoaderVerifier implementation.
   
   (C) ultrashot 2012
*/
#pragma once
#ifndef ACCOUNTMANAGER_H
#define ACCOUNTMANAGER_H

/* returns TRUE if account is privileged */
BOOL GetPrivileged(LPWSTR account);

/* Add account to privileged group */
VOID AddToPrivilegedGroup(LPWSTR account);

/* Removes account from privileged group */
VOID RemoveFromPrivilegedGroup(LPWSTR account);

/* returns TRUE if full trust mode is enabled */
BOOL IsFullTrustModeEnabled();

/* Changes full trust mode settings */
VOID SetFullTrustEnabled(BOOL mode);

/* Adds account to third party app group */
VOID AddToThirdPartyGroup(LPWSTR account);

/* Removes account from third party app group */
VOID RemoveFromThirdPartyGroup(LPWSTR account);

/* Checks if account is in third-party app group */
BOOL IsInThirdPartyGroup(LPWSTR account);

#endif
