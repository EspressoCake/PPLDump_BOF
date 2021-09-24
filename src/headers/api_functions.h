#pragma once

#include <windows.h>
#include <strsafe.h>
#include <aclapi.h>
#include <rpcdce.h>
#include "syscalls.h"
#include "beacon.h"



// Temporary includes for prototypes

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)


WINBASEAPI  void*       __cdecl     MSVCRT$memset (void* _Dst, int _Val, size_t Size);
WINBASEAPI  int         __cdecl     MSVCRT$swprintf (wchar_t* _Buffer, size_t _BufferCount, const wchar_t* _Format, ...);
WINBASEAPI  int         __cdecl     MSVCRT$_wcsicmp (const wchar_t *_Str1,const wchar_t *_Str2);
WINBASEAPI  size_t      __cdecl     MSVCRT$wcslen (const wchar_t* String);
WINBASEAPI  wchar_t*    __cdecl     MSVCRT$wcsncat (wchar_t* _Destination, const wchar_t *Source, size_t Count);
WINBASEAPI  wchar_t*    __cdecl     MSVCRT$wcsncpy (wchar_t* _Destination, const wchar_t* _Source, size_t _Count);
WINBASEAPI  BOOL        WINAPI      KERNEL32$GetExitCodeProcess (HANDLE hProcess, LPDWORD lpExitCode);
WINBASEAPI  HMODULE     WINAPI      KERNEL32$GetModuleHandleW (LPCWSTR lpModuleName);
WINBASEAPI  FARPROC     WINAPI      KERNEL32$GetProcAddress (HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI  HINSTANCE   WINAPI      KERNEL32$LoadLibraryW (LPCWSTR);
WINBASEAPI  RPC_STATUS  WINAPI      RPCRT4$UuidCreate (UUID*);
WINBASEAPI  RPC_STATUS  WINAPI      RPCRT4$UuidToStringW (IN const UUID*, _Outptr_ RPC_WSTR __RPC_FAR* StringUuid);
WINBASEAPI  RPC_STATUS  WINAPI      RPCRT4$RpcStringFreeW (RPC_WSTR*);
WINBASEAPI  FARPROC     WINAPI      KERNEL32$CreateEventW(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);