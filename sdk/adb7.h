#pragma once
#ifndef ADB7_H
#define ADB7_H


typedef DWORD         ACCTID;
typedef ACCTID       *PACCTID;
typedef ACCTID const *PCACCTID;


#ifdef __cplusplus
extern "C" {
#endif

typedef DWORD PRIVILEGE, *PPRIVILEGE;
#define ISEXTPRIVILEGE(x) ((x) & 0x80000000)

#define DEFAULT_DATABASE_NAME TEXT("accountdb.vol")

// values for Account Flags
#define ACCT_FLAG_GROUP             0x1
#define ACCT_FLAG_TOPLEVEL          0x2

#define ACCT_FLAG_MASK  (ACCT_FLAG_GROUP | ACCT_FLAG_TOPLEVEL )

// well known accounts. Can't create accounts with these names
//
#define ACCT_NAME_CREATOR_OWNER     L"Owner"
#define ACCT_NAME_CREATOR_GROUP     L"Group"

// Account name string maximun size, it includes NULL terminater.
#define ADB_MAX_ACCOUNTNAME_SIZE 128

/// <summary>
///     Create a new account of the specified type.
/// </summary>
/// <param name="pszName">
///     Account name. Must be a valid non-NULL name.
/// </param>
/// <param name="dwAcctFlags">
///     Bit mask of one or more of the following account flags:
///         0 - chamber account
///         ACCT_FLAG_GROUP - group account
///         ACCT_FLAG_TOPLEVEL - account cannot be added to a group
/// </param>
/// <result>
///     Returns ERROR_SUCCESS if the account has been created.
///     ERROR_INVALID_PARAMETER if some of parameters are invalid
///     ERROR_INVALID_ACCOUNT_NAME if the account name is invalid or it is one of reserved account name
///     ERROR_GROUP_EXISTS if the new group already exists
///     ERROR_USER_EXISTS if the new chamber account already exists
/// </result>
/// <remarks>
///     The caller must has TCB privilege
/// </remarks>
LONG 
ADBCreateAccount(
    __in LPCWSTR pszName,
    DWORD dwAcctFlags,
    __reserved DWORD Reserved);

/// <summary>
///     Delete the named account and its all group memberships
/// </summary>
/// <param name="pszName">
///     Account name. Must be a valid non-NULL name.
/// </param>
/// <result>
///     Returns ERROR_SUCCESS if the account has been deleted.
///     ERROR_INVALID_PARAMETER if some of parameters are invalid
///     ERROR_NO_SUCH_USER if the account name can't be found or invalid
/// </result>
/// <remarks>
///     The caller must has TCB privilege.
/// </remarks>
LONG 
ADBDeleteAccount(
    __in LPCWSTR pszName);

#define ADB_DWORD        0x0000
#define ADB_STRING       0x10000
#define ADB_MSTRING      0x20000
#define ADB_BINARY       0x30000
#define ADBTYPE(propertyId) ((0xf0000 & (propertyId)) >> 16)

#define ADBPROP_ACCTID              (ADB_DWORD   | 0x5)
#define ADBPROP_ACCTFLAGS           (ADB_DWORD   | 0x6)
#define ADBPROP_PRIVILEGES          (ADB_DWORD   | 0x7)
#define ADBPROP_EXTPRIVILEGES       (ADB_BINARY  | 0x8)
#define ADBPROP_GROUPS              (ADB_MSTRING | 0xa)
#define ADBPROP_GROUPMEMBERS        (ADB_MSTRING | 0xb)
#define ADBPROP_FRIENDLYNAME        (ADB_STRING  | 0xc)

typedef struct _ADB_BLOB {
    DWORD propertyId;
    VOID    *pData;
    DWORD   cbData;
} ADB_BLOB, *PADB_BLOB;

/// <summary>
///     Read an account property.
/// </summary>
/// <param name="pszName">
///     Account name. Must be a valid non-NULL name.
/// </param>
/// <param name="propertyId">
///     property identifier. See table for valid property identifiers.
///         PropertyId            Description         Read/Write  Type
///         ADBPROP_ACCTID        Account Identifier  R           DWORD
///         ADBPROP_ACCTFLAGS     Account Flags       R           DWORD
///         ADBPROP_PRIVILEGES    Basic Privileges    R/W         DWORD
///         ADBPROP_EXTPRIVILEGES Extended Privileges R/W         Binary
///         ADBPROP_FRIENDLYNAME  Friendly Name       R/W         String
///         ADBPROP_GROUPS        Groups              R           Multi String
///         ADBPROP_GROUPMEMBERS  Members             R           Multi String
/// </param>
/// <param name="pcbPropertyValue">
///     size in bytes of property value buffer on input. Filled with actual size in bytes of property value on output
/// </param>
/// <param name="pValue">
///     Property value. This buffer must be aligned appropriately for the expected type.
/// </param>
/// <result>
///     Returns ERROR_SUCCESS if account property has been filled into <c>pValue</c>.
///     ERROR_INVALID_PARAMETER if some of parameters are invalid
///     ERROR_INSUFFICIENT_BUFFER if <c>pcbPropertyValue</c> is less than required size.
///     ERROR_NO_SUCH_USER if the account name can't be found or invalid
/// </result>
LONG
ADBGetAccountProperty(
    __in PCWSTR pszName,
    DWORD propertyId,
    __inout PDWORD pcbPropertyValue,
    __out_bcount_opt(*pcbPropertyValue) PVOID pValue);

/// <summary>
///    Write one or more account properties. See <c>ADBGetAccountProperty</c> for a list of possible property Ids. 
///     Only those that are R/W may be set. No change is made to the account if there as an error writing any property.
/// </summary>
/// <param name="pszName">
///     Account name. Must be a valid non-NULL name.
/// </param>
/// <param name="cProperties">
///     number of properties to be set
/// </param>
/// <param name="rgProperties">
///     An array of <c>ADB_BLOB</c> structures, each describing one property Id and the corresponding value.
/// </param>
/// <result>
///     Returns ERROR_SUCCESS if the account has been deleted.
///     ERROR_INVALID_PARAMETER if some of parameters are invalid
///     ERROR_NO_SUCH_USER if the account name can't be found or invalid
/// </result>
/// <remarks>
///     The caller must has TCB privilege.
/// </remarks>
LONG
ADBSetAccountProperties(
    __in PCWSTR pszName,
    DWORD cProperties,
    __in_ecount(cProperties) ADB_BLOB *rgProperties);

/*
    This structure is used with ADBGetAccountSecurityInfo, to get Groups and Privileges for all groups that the account is
    directly or indirectly a member of.  The pointers pAllExtPrivileges and pmszAllGroups point to allocation points behind
    the structure passed in, therefore the actual buffer allocated to hold the structure needs to have enough space at the 
    end for these buffers: 
    | ----- ADB_SECURITY_INFO ---- | -- cAllExtPrivileges -- | --cAllGroups -- |
                                   ^pAllExtPrivileges        ^pmszAllGroups
    and as you can see, pAllExtPrivileges points to the end of the ADB_SECURITY_INFO structure (or NULL if there are none), 
    and pmszAllGroups points to the beginning of cAllGroups. 
    Therefore the allocation size should be: sizeof(ADB_SECURITY_INFO) + cAllExtPrivileges*sizeof(PRIVILEGE) + cAllGroups
    
*/
typedef struct _ADB_SECURITY_INFO
{
    DWORD version;      // must be 1
    DWORD accountFlags; // account flags
    // the following are effective groups and privileges
    // obtained by expanding the groups that the account belongs to
    DWORD cAllGroups;
    PWSTR pmszAllGroups;
    PRIVILEGE allBasicPrivileges;
    DWORD cAllExtPrivileges;
    PRIVILEGE *pAllExtPrivileges;
} ADB_SECURITY_INFO;

/// <summary>
///     Get Groups and Privileges for all groups that the account is directly or indirectly a member of. 
/// </summary>
/// <param name="pszName">
///     Account name. Must be a valid non-NULL name.
/// </param>
/// <param name="pcbBuf">
///     size in bytes of security info buffer on input. Filled with actual size in bytes of ADB_SECURITY_INFO on output
/// </param>
/// <param name="pSecurityInfo">
///     pointer to a buffer to receive the response. The function returns a 
///     <c>ADB_SECURITY_INFO</c> struct in this buffer, followed by data referenced by the structure.
/// </param>
/// <result>
///     Returns ERROR_SUCCESS if account property has been filled into <c>pSecurityInfo</c>
///     ERROR_NO_SUCH_USER if the account name can't be found or invalid
///     ERROR_INVALID_PARAMETER if some of parameters are invalid
///     ERROR_INSUFFICIENT_BUFFER if <c>pcbBuf</c> is less than required size.
/// </result>
LONG ADBGetAccountSecurityInfo(
    __in PCWSTR pszName,
    __inout PDWORD pcbBuf,
    __out_bcount_opt(*pcbBuf) ADB_SECURITY_INFO *pSecurityInfo);

/// <summary>
///     Add an account to a group.
/// </summary>
/// <param name="pszName">
///     Account name. Must be a valid non-NULL name.
/// </param>
/// <param name="pszGroupName">
///     Group name. Must be a valid non-NULL name.
/// </param>
/// <result>
///     Returns ERROR_SUCCESS if the account has been added into the specified group
///     ERROR_INVALID_PARAMETER if some of parameters are invalid
///     ERROR_NO_SUCH_USER if the account name can't be found or invalid
///     ERROR_NO_SUCH_GROUP if the group name can't be found or invalid
///     ERROR_MEMBER_IN_GROUP if the account is already in the group
/// </result>
/// <remarks>
///     The caller must has TCB privilege.
/// </remarks>
LONG ADBAddAccountToGroup(
    __in PCWSTR pszName,
    __in PCWSTR pszGroupName);

/// <summary>
///     Remove an account from a group. 
/// </summary>
/// <param name="pszName">
///     Account name. Must be a valid non-NULL name.
/// </param>
/// <param name="pszGroupName">
///     Group name. Must be a valid non-NULL name.
/// </param>
/// <result>
///     Returns ERROR_SUCCESS if the account has been removed from the specified group
///     ERROR_INVALID_PARAMETER if some of parameters are invalid
///     ERROR_NO_SUCH_USER if the account name can't be found or invalid
///     ERROR_NO_SUCH_GROUP if the group name can't be found or invalid
///     ERROR_MEMBER_NOT_IN_GROUP if the account is not in the group
/// </result>
/// <remarks>
///     The caller must has TCB privilege.
/// </remarks>
LONG ADBRemoveAccountFromGroup(
    __in PCWSTR pszName,
    __in PCWSTR pszGroupName);

/// <summary>
///     Enumerate all accounts in database. If there are accounts added or removed while the enumeration is in progress, 
///     the changes may not be reported.
/// </summary>
/// <param name="dwFlags">
///     must be zero
/// </param>
/// <param name="pszPrevName">
///     name of previously enumerated name. Set to NULL when starting enumeration.
/// </param>
/// <param name="pcchNextName">
///     The size of <c>pszNextName</c> buffer in characters on input
///     The number of characters in the account name (including trailing NULL character) on output.
/// </param>
/// <param name="pszNextName">
///     next enumerated name.
/// </param>
/// <result>
///     Returns ERROR_SUCCESS if the account has been deleted.
///     ERROR_INVALID_PARAMETER if some of parameters are invalid
///     ERROR_NO_SUCH_USER if the account name in <c>pszPrevName</c> can't be found
///     ERROR_INSUFFICIENT_BUFFER if <c>pszNextName</c> is less than required size.
/// </result>
LONG ADBEnumAccounts(
    DWORD dwFlags,
    __in_opt PCWSTR pszPrevName,
    __inout PDWORD pcchNextName,
    __out_ecount_opt(*pcchNextName) PWSTR pszNextName);

/// <summary>
///     Get AccountID from the name
/// </summary>
/// <param name="pszName">
///     Account name. Must be a valid non-NULL name.
/// </param>
/// <param name="pAccountID">
///     The buffer for account ID, it must not be NULL
/// </param>
/// <result>
///     Returns ERROR_SUCCESS if the account id has been returned
///     ERROR_INVALID_PARAMETER if some of parameters are invalid
///     ERROR_NO_SUCH_USER if the account name can't be found or invalid
/// </result>
LONG ADBAccountIDFromName(__in PCWSTR pszName, __out PACCTID pAccountID);

/// <summary>
///     Get name from the AccountID.
/// </summary>
/// <param name="pAccountID">
///     A pointer to account id. Must be a valid non-NULL pointer
/// </param>
/// <param name="pszName">
///     The buffer for account name
/// </param>
/// <param name="pcchName">
///     The size of the <c>pszName</c> buffer in characters on input.
///     The number of characters in the account name (including trailing NULL character) on output.
/// </param>
/// <result>
///     Returns ERROR_SUCCESS if the account has been deleted.
///     ERROR_INVALID_PARAMETER if some of parameters are invalid
///     ERROR_INSUFFICIENT_BUFFER if <c>pcchName</c> is less than required size.
///     ERROR_NO_SUCH_USER if the account name in <c>pszPrevName</c> can't be found
/// </result>
LONG ADBNameFromAccountID(
    __in PCACCTID pAccountID,
    __out_ecount_opt(*pcchName) PWSTR pszName,
    __inout PDWORD pcchName);

/// <summary>
///     Enumerate member account from a group.
/// </summary>
/// <param name="pszGroupName">
///     name for the group acount 
/// </param>
/// <param name="pszPrevName">
///     name of previously enumerated name. Set to NULL when starting enumeration.
/// </param>
/// <param name="pcchNextName">
///     The size of <c>pszNextName</c> buffer in characters on input.
///     The number of characters in the account name (including trailing NULL character) on output.
/// </param>
/// <param name="pszNextName">
///     next enumerated name.
/// </param>
/// <result>
///     Returns ERROR_SUCCESS if the account has been deleted.
///     ERROR_INVALID_PARAMETER if some of parameters are invalid
///     ERROR_NO_SUCH_USER if the account name in <c>pszPrevName</c> can't be found
///     ERROR_INSUFFICIENT_BUFFER if <c>pszNextName</c> is less than required size.
/// </result>
LONG ADBEnumAccountsInGroup(
    __in PCWSTR pszGroupName,
    __in PCWSTR pszPrevName,
    __out_ecount_opt(*pcchNextName) PWSTR pszNextName,
    __inout PDWORD pcchNextName);

/// <summary>
///     Get the account's friendly name from the account database.
/// </summary>
/// <param name="pcszAccountName">
///     Account name. Must be a valid non-NULL name.
/// </param>
/// <param name="pszFriendlyName">
///     The account friendly name
/// </param>
/// <param name="pcchFriendlyName">
///     The size of <c>pszFriendlyName</c> buffer in characters on input.
///     The number of characters in the account friendly name (including trailing NULL character) on output.
/// </param>
/// <result>
///     Returns ERROR_SUCCESS if account friendly name has been filled into <c>pszFriendlyName</c>.
///     ERROR_INVALID_PARAMETER if some of parameters are invalid
///     ERROR_INSUFFICIENT_BUFFER if <c>pcchFriendlyName</c> is less than required size.
///     ERROR_NO_SUCH_USER if the account name can't be found or invalid
/// </result>
#ifndef MIDL_PASS
FORCEINLINE
LONG
ADBGetAccountFriendlyName(
    __in PCWSTR pcszAccountName,
    __out_ecount_opt(*pcchFriendlyName) PWSTR pszFriendlyName,
    __inout PDWORD pcchFriendlyName)
{
    // Can't include strsafe.h, so define a local const
    const DWORD c_cchMax = 0xffffffff / sizeof(WCHAR);
    DWORD cbFriendlyName = 0;
    LONG lResult = ERROR_SUCCESS;

    if (!pcchFriendlyName || *pcchFriendlyName > c_cchMax)
    {
        return ERROR_INVALID_PARAMETER;
    }

    cbFriendlyName = (*pcchFriendlyName) * sizeof(WCHAR);
    lResult = ADBGetAccountProperty(pcszAccountName,
                                ADBPROP_FRIENDLYNAME,
                                &cbFriendlyName,
                                (PVOID)pszFriendlyName);
    *pcchFriendlyName = cbFriendlyName / sizeof(WCHAR);
    return lResult;
}
#else
LONG
ADBGetAccountFriendlyName(
    __in PCWSTR pcszAccountName,
    __out_ecount_opt(*pcchFriendlyName) PWSTR pszFriendlyName,
    __inout PDWORD pcchFriendlyName);
#endif

/// <summary>
///     Normalize an account name.
/// </summary>
/// <param name="pszAccountName">
///     Account name to be normalized.
/// </param>
/// <param name="pszNormalizedAccountName">
///     On input, if pszNormalizedAccountName is NULL, *pcchNormalizedAccountName will
///     return the required buffer size for pszNormalizedAccountName (including the terminating NULL) in characters.
///     On output, it represents the normalized account name. 
/// </param>
/// <param name="pcchNormalizedAccountName">
///     On input, it points to the buffer size of pszNormalizedAccountName in characters.
///     On output, it points to the actual number of characters (including the terminating NULL) written to pszNormalizedAccountName.
/// </param>
/// <result>
///     ERROR_SUCCESS - Success, pszNormalizedAccountName contains the normalized name.
///     ERROR_INVALID_PARAMETER - Invalid argument.
///     ERROR_INSUFFICIENT_BUFFER - The size of the buffer pszNormalizedAccountName is insufficient.
/// </result>

LONG ADBNormalizeAccountName(
    __in_z PCWSTR pszAccountName, 
    __inout_ecount_opt (*pcchNormalizedAccountName) PWSTR pszNormalizedAccountName, 
    __inout DWORD *pcchNormalizedAccountName);

/// <summary>
///     Denormalize an account name that came from ADBNormalizeAccountName or from policy XML
/// </summary>
/// <param name="pszAccountName">
///     Account name to be denormalized.
/// </param>
/// <param name="pszDenormalizedAccountName">
///     On input, if pszDenormalizedAccountName is NULL, *pcchDenormalizedAccountName will
///     return the required buffer size for pszDenormalizedAccountName (including the terminating NULL) in characters.
///     On output, it represents the denormalized account name. 
/// </param>
/// <param name="pcchNormalizedAccountName">
///     On input, it points to the buffer size of pszDenormalizedAccountName in characters.
///     On output, it points to the actual number of characters (including the terminating NULL) written to pszDenormalizedAccountName.
/// </param>
/// <result>
///     ERROR_SUCCESS - Success, pszNormalizedAccountName contains the normalized name.
///     ERROR_INVALID_PARAMETER - Invalid argument.
///     ERROR_BAD_FORMAT - The argument is in bad format.
///     ERROR_INSUFFICIENT_BUFFER - The size of the buffer pszNormalizedAccountName is insufficient.
/// </result>
LONG ADBDenormalizeAccountName(
    __in_z                                              LPCWSTR pszAccountName, 
    __inout_ecount_opt (*pcchDenormalizedAccountName)   LPWSTR  pszDenormalizedAccountName, 
    __inout                                             DWORD*  pcchDenormalizedAccountName);

/// <summary>
///     Hex encode a name after upper casing it.
/// </summary>
/// <param name="psztName">
///     Name to be hex encoded.
/// </param>
/// <param name="pszEncodedName">
///     On input, if pszEncodedName is NULL, *pcchEncodedName will
///     return the required buffer size for pszEncodedName (including the terminating NULL) in characters.
///     On output, it represents the hex encoded name. 
/// </param>
/// <param name="pcchEncodedName">
///     On input, it points to the buffer size of pszEncodedName in characters.
///     On output, it points to the actual number of characters (including the terminating NULL) written to pszEncodedName.
/// </param>
/// <result>
///     ERROR_SUCCESS - Success, pszEncodedName contains the hex encoded name.
///     ERROR_INVALID_PARAMETER - Invalid argument.
///     ERROR_INSUFFICIENT_BUFFER - The size of the buffer pszEncodedName is insufficient.
/// </result>

LONG ADBHexEncodeName(
    __in_z PCWSTR pszName, 
    __inout_ecount_opt (*pcchEncodedName) PWSTR pszEncodedName, 
    __inout DWORD *pcchEncodedName);

/// <summary>
///    decode a hex encoded uppercase name that came from ADBEncodeName.
/// </summary>
/// <param name="psztName">
///     hex encoded upper case name
/// </param>
/// <param name="pszDecodedName">
///     On input, if pszDecodedName is NULL, *pcchDecodedName will
///     return the required buffer size for pszDecodedName (including the terminating NULL) in characters.
///     On output, it represents the decoded name. 
/// </param>
/// <param name="pcchDeodedName">
///     On input, it points to the buffer size of pszDecodedName in characters.
///     On output, it points to the actual number of characters (including the terminating NULL) written to pszDecodedName.
/// </param>
/// <result>
///     ERROR_SUCCESS - Success, pszDecodedName contains the encoded name.
///     ERROR_INVALID_PARAMETER - Invalid argument.
///     ERROR_BAD_FORMAT - The argument is in bad format.
///     ERROR_INSUFFICIENT_BUFFER - The size of the buffer pszDecodedName is insufficient.
/// </result>
LONG ADBHexDecodeName(
    __in_z                                  LPCWSTR pszName, 
    __inout_ecount_opt (*pcchDecodedName)   LPWSTR  pszDecodedName, 
    __inout                                 DWORD* pcchDecodedName);

/// <summary>
///    Flush account database
/// </summary>
/// <result>
///     ERROR_SUCCESS - Success, otherwise it return an error code
/// </result>
/// <remarks>
///     The caller must has TCB privilege
/// </remarks>
LONG ADBFlush();

// function pointer typedefs for above functions, in case they are dynamically loaded
typedef LONG (* PFNADBCreateAccount)(IN LPCWSTR pszName, IN DWORD dwAcctFlags, IN DWORD Reserved);
typedef LONG (* PFNADBDeleteAccount)(IN LPCWSTR pszName);
typedef LONG (* PFNADBGetAccountProperty)(IN PCWSTR pszName, IN DWORD propertyId, IN OUT PDWORD pcbPropertyValue, OUT PVOID pValue);
typedef LONG (* PFNADBSetAccountProperties)(IN PCWSTR pszName, IN DWORD cProperties, IN ADB_BLOB * rgProperties);
typedef LONG (* PFNADBGetAccountSecurityInfo)(IN PCWSTR pszName, IN OUT PDWORD pcbBuf, OUT ADB_SECURITY_INFO * pSecurityInfo);
typedef LONG (* PFNADBAddAccountToGroup)(IN PCWSTR pszName, IN PCWSTR pszGroupName);
typedef LONG (* PFNADBRemoveAccountFromGroup)(IN PCWSTR pszName, IN PCWSTR pszGroupName);
typedef LONG (* PFNADBEnumAccounts)(IN DWORD dwFlags, IN PCWSTR pszPrevName, IN OUT PDWORD pcchNextName, OUT PWSTR pszNextName);
typedef LONG (* PFNADBAccountIDFromName)( IN PCWSTR pszName,OUT PACCTID pAccountID);
typedef LONG (* PFNADBNameFromAccountID)( IN PCACCTID pAccountID, OUT PWSTR pszName, IN OUT PDWORD pcchName) ;
typedef LONG (* PFNADBEnumAccountsInGroup)(PCWSTR pszGroupName, PCWSTR pszPrevName, PWSTR pszNextName, PDWORD pcchNextName);
typedef LONG (* PFNADBFlush)();

#ifdef __cplusplus
}
#endif



// our definitions
#define CURRENTPROCESS ((HANDLE)0x42)


ACCTID GetAccount(HANDLE hProcess);
BOOL GetAccountName(ACCTID accountID, LPWSTR lpwszAccountName, DWORD dwAccountNameLength);
BOOL GetNormalizedAccountName(ACCTID accountID, LPWSTR lpwszAccountName, DWORD dwAccountNameLength);
ACCTID Name2AccountID(LPWSTR lpwszAccountName);

#endif
