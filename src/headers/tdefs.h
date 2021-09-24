#pragma once

#include <windows.h>
#include <strsafe.h>
#include <aclapi.h>
#include "syscalls.h"


#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

typedef BOOL    (WINAPI *_AdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
typedef WINBOOL (WINAPI *_ConvertSidToStringSidW)(IN PSID Sid, _Outptr_ LPWSTR* StringSid);
typedef WINBOOL (WINAPI *_ConvertStringSidToSidW)(IN LPCWSTR StringSid, _Outptr_ PSID* Sid);
typedef WINBOOL (WINAPI *_CopySid)(DWORD nDestinationSidLength, PSID pDestinationSid, PSID pSourceSid);
typedef WINBOOL (WINAPI *_DuplicateTokenEx)(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken);
typedef BOOL    (WINAPI *_LookupPrivilegeValueW)(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
typedef DWORD   (WINAPI *_GetSecurityInfo)(HANDLE handle, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID *ppsidOwner, PSID *ppsidGroup, PACL *ppDacl, PACL *ppSacl, PSECURITY_DESCRIPTOR *ppSecurityDescriptor);
typedef PDWORD  (WINAPI *_GetSidSubAuthority)(PSID, DWORD);
typedef PUCHAR  (WINAPI *_GetSidSubAuthorityCount)(PSID);
typedef WINBOOL (WINAPI *_GetTokenInformation)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
typedef WINBOOL (WINAPI *_InitializeSecurityDescriptor)(PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision);
typedef BOOL    (WINAPI *_LookupAccountSidW)(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
typedef WINBOOL (WINAPI *_LookupPrivilegeNameW)(LPCWSTR lpSystemName, PLUID lpLuid, LPWSTR lpName, LPDWORD cchName);
typedef WINBOOL (WINAPI *_OpenProcessToken)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
typedef WINBOOL (WINAPI *_OpenThreadToken)(HANDLE hThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle);
typedef WINBOOL (WINAPI *_RevertToSelf)(VOID);
typedef WINBOOL (WINAPI *_SetKernelObjectSecurity)(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor);
typedef WINBOOL (WINAPI *_SetSecurityDescriptorDacl)(PSECURITY_DESCRIPTOR pSecurityDescriptor, WINBOOL bDaclPresent, PACL pDacl, WINBOOL bDaclDefaulted);
typedef WINBOOL (APIENTRY *_SetThreadToken)(PHANDLE Thread, HANDLE Token);
typedef HANDLE  (WINAPI *_CreateFileTransactedW)(IN LPCWSTR, IN DWORD, IN DWORD, __in_opt LPSECURITY_ATTRIBUTES, IN DWORD, IN DWORD, __in_opt HANDLE, IN HANDLE, __in_opt PUSHORT, _Reserved_ PVOID);
typedef HANDLE  (WINAPI *_CreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef WINBOOL (WINAPI *_DefineDosDeviceW)(DWORD dwFlags, LPCWSTR lpDeviceName, LPCWSTR lpTargetPath);
typedef WINBOOL (WINAPI *_FindClose)(HANDLE hFindFile);
typedef HANDLE  (WINAPI *_FindFirstFileW)(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
typedef WINBOOL (WINAPI *_FindNextFileW)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
typedef DWORD   (WINAPI *_GetCurrentProcessId)(VOID);
typedef HANDLE  (WINAPI *_GetCurrentThread)(VOID);
typedef DWORD   (WINAPI *_GetFileAttributesW)(LPCWSTR);
typedef DWORD   (WINAPI *_GetFileSize)(HANDLE hFile, LPDWORD lpFileSizeHigh);
typedef HMODULE (WINAPI *_GetModuleHandleA)(LPCSTR lpModuleName);
typedef FARPROC (WINAPI *_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef UINT    (WINAPI *_GetSystemDirectoryW)(LPWSTR lpBuffer, UINT uSize);
typedef HLOCAL  (WINAPI *_LocalAlloc)(UINT, SIZE_T);
typedef HLOCAL  (WINAPI *_LocalFree)(HLOCAL);
typedef int     (WINAPI *_lstrlenW)(LPCWSTR lpString);
typedef HANDLE  (WINAPI *_OpenProcess)(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
typedef DWORD   (WINAPI *_GetLastError)(VOID);
typedef WINBOOL (WINAPI *_WriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
typedef HMODULE (WINAPI *_GetModuleHandleW)(LPCWSTR lpModuleName);
typedef FARPROC (WINAPI *_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef WINBOOL (WINAPI *_CreateProcessAsUserW)(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef DWORD   (WINAPI *_WaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);

// Additions
typedef FARPROC (WINAPI *_CreateEventW)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);

typedef struct _Function_Pointer_Struct_ {
    _CreateEventW StructCreateEventW;
    _CreateProcessAsUserW StructCreateProcessAsUserW;
    _WaitForSingleObject StructWaitForSingleObject;
    _OpenThreadToken StructOpenThreadToken;
    _GetModuleHandleW StructGetModuleHandleW;
    _GetProcAddress StructGetProcAddress;
    _AdjustTokenPrivileges StructAdjustTokenPrivileges;
    _ConvertSidToStringSidW StructConvertSidToStringSidW;
    _ConvertStringSidToSidW StructConvertStringSidToSidW;
    _CopySid StructCopySid;
    _DuplicateTokenEx StructDuplicateTokenEx;
    _LookupPrivilegeValueW StructLookupPrivilegeValueW;
    _GetSecurityInfo StructGetSecurityInfo;
    _GetSidSubAuthority StructGetSidSubAuthority;
    _GetSidSubAuthorityCount StructGetSidSubAuthorityCount;
    _GetTokenInformation StructGetTokenInformation;
    _InitializeSecurityDescriptor StructInitializeSecurityDescriptor;
    _LookupAccountSidW StructLookupAccountSidW;
    _LookupPrivilegeNameW StructLookupPrivilegeNameW;
    _OpenProcessToken StructOpenProcessToken;
    _RevertToSelf StructRevertToSelf;
    _SetKernelObjectSecurity StructSetKernelObjectSecurity;
    _SetSecurityDescriptorDacl StructSetSecurityDescriptorDacl;
    _SetThreadToken StructSetThreadToken;
    _CreateFileTransactedW StructCreateFileTransactedW;
    _CreateFileW StructCreateFileW;
    _DefineDosDeviceW StructDefineDosDeviceW;
    _FindClose StructFindClose;
    _FindFirstFileW StructFindFirstFileW;
    _FindNextFileW StructFindNextFileW;
    _GetCurrentProcessId StructGetCurrentProcessId;
    _GetCurrentThread StructGetCurrentThread;
    _GetFileAttributesW StructGetFileAttributesW;
    _GetFileSize StructGetFileSize;
    _GetModuleHandleA StructGetModuleHandleA;
    _GetSystemDirectoryW StructGetSystemDirectoryW;
    _LocalAlloc StructLocalAlloc;
    _LocalFree StructLocalFree;
    _lstrlenW StructlstrlenW;
    _OpenProcess StructOpenProcess;
    _GetLastError StructGetLastError;
    _WriteFile StructWriteFile;
} FUNCTION_POINTER_STRUCT, *PFUNCTION_POINTER_STRUCT;