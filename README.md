# macOS EDR Evasion

A research-grade macOS implant demonstrating multi-layered bypass techniques against Elastic Defend. Built as a principal-level red team portfolio piece covering diskless execution, memory-protected sleep, raw BSD socket syscalls, and AES-GCM-encrypted C2 messaging.

[![Go Version](https://img.shields.io/badge/go-%3E%3D1.22-blue)](https://golang.org)
[![Platform](https://img.shields.io/badge/platform-macos%20%7C%20linux-lightgrey)](https://www.apple.com/macos)

---

## Table of Contents

- [Objective](#objective)
- [Architecture](#architecture)
- [Technical Deep Dive](#technical-deep-dive)
  - [Runtime Configuration Encryption](#1-runtime-configuration-encryption)
  - [Diskless Execution](#2-diskless-execution)
  - [Raw BSD Socket Syscalls](#3-raw-bsd-socket-syscalls)
  - [Memory-Protected Sleep](#4-memory-protected-sleep)
  - [Encrypted C2 Channel](#5-encrypted-c2-channel)
  - [Anti-Debug](#6-anti-debug-macos)
  - [Jittered Beaconing](#7-jittered-beaconing)
- [Build](#build)
- [Demo](#demo)
- [Detection Engineering](#detection-engineering)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Disclaimer](#disclaimer)

---

## Objective

Simulate an advanced threat actor operating on a macOS enterprise endpoint protected by Elastic Defend. The implant achieves initial execution, maintains encrypted C2 communications, survives without disk artifacts, and defeats memory scanning—all while generating **zero behavioral alerts** in the EDR console.

**Target EDR:** Elastic Defend (self-hosted, macOS agent)  
**Target OS:** macOS Sonoma (Darwin/arm64)  
**Attacker Platform:** Kali Linux VM

---

## Architecture

```
redteam-portfolio/
├── cmd/
│   ├── c2server/          # Go-based C2 listener (Kali)
│   └── implant/           # macOS implant binary
├── pkg/
│   ├── crypto/            # AES-256-GCM primitives
│   ├── c2/                # Raw BSD socket transport
│   ├── comms/             # Encrypted message framing
│   └── evasion/           # macOS evasion primitives
├── docs/
│   ├── ATTACK_CHAIN.md    # Step-by-step engagement narrative
│   └── DETECTION.md       # Purple team detection recommendations
└── scripts/
    └── demo_auto.py       # Demo auto-typer (optional)
```

---

## Technical Deep Dive

### 1. Runtime Configuration Encryption

The C2 address (`192.168.1.165:8443`) and the session encryption key are embedded in the binary as **AES-256-GCM ciphertext**. At runtime, the implant decrypts these values using a hardcoded 32-byte key derived from a SHA-256 hash.

**Why:** This defeats static string analysis. Running `strings`, `rabin2 -zz`, or ` floss` against the Mach-O binary reveals only high-entropy ciphertext—no C2 infrastructure, no IP addresses, no ports.

**Software mechanism:**
- `pkg/crypto/aes.go` provides `DecryptString(ciphertextHex, keyHex)`
- The hex-encoded ciphertext and key are compile-time constants in `cmd/implant/main.go`
- Decryption occurs in-memory at process startup; plaintext exists only on the heap briefly before being moved into a secure buffer

### 2. Diskless Execution

Immediately after startup, the implant calls `os.Remove(os.Args[0])`. On Unix-like kernels (including Darwin), unlinking a running executable's inode is permitted because the kernel maintains a reference count on the underlying vnode. The directory entry disappears, but the process image remains mapped in memory until termination.

**Why:** Forensic disk acquisition (e.g., `dd`, `ftk imager`, `osx-collect`) finds no binary artifact. Hash-based IOCs and YARA rules targeting the file on disk are useless.

**Software mechanism:**
- `os.Remove(os.Args[0])` in `cmd/implant/main.go`
- No secondary dropper or staging file is written

### 3. Raw BSD Socket Syscalls

Standard Go network code (`net.Dial`) routes through `libSystem`, where EDR agents commonly place userland API hooks to inspect arguments and destinations. To bypass these hooks, the implant creates a TCP connection using direct BSD socket syscalls via `golang.org/x/sys/unix`:

```go
fd, _ := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
unix.Connect(fd, &unix.SockaddrInet4{...})
unix.Read(fd, buf)
unix.Write(fd, data)
```

**Why:** By avoiding `libSystem`'s `connect()` wrapper, the implant evades any userland shim that logs destination IPs, ports, or socket options. The EDR still sees the socket creation via kernel telemetry (ESF, kexts, or eBPF), but the high-fidelity argument inspection performed by userland hooks is bypassed.

**Software mechanism:**
- `pkg/c2/rawsock.go` implements `DialRaw()`, `Read()`, and `Write()`
- `Poll`-based read with a 30-second timeout prevents indefinite hanging on dead connections

### 4. Memory-Protected Sleep

When the C2 connection drops, the implant must sleep before reconnecting. During this idle window, EDR memory scanners (e.g., Elastic's malware memory protection, third-party MDR tools) may sweep process address space for implants, shellcode, or configuration strings.

The implant uses a **SecureBuffer** allocated via `mmap(MAP_ANON | MAP_PRIVATE, PROT_READ | PROT_WRITE)`:

1. The decrypted C2 address is copied into the buffer
2. On sleep: the buffer is encrypted in-place with AES-256-GCM
3. `mprotect(addr, len, PROT_NONE)` is called, making the page completely inaccessible
4. The kernel raises a segmentation fault if any scanner or debugger touches this page
5. On wake: `mprotect` restores `PROT_READ | PROT_WRITE`, and the buffer is decrypted

**Why:** This defeats string-based memory scans and live memory forensics during the implant's idle periods. The sensitive data is either encrypted or inaccessible.

**Software mechanism:**
- `pkg/evasion/memory.go` implements `SecureBuffer` with `Lock()`, `Unlock()`, and `Sleep()`
- Page alignment is handled automatically using `unix.Getpagesize()`

### 5. Encrypted C2 Channel

All C2 traffic is framed with **AES-256-GCM**. The frame format is:

```
[ 4 bytes: big-endian length of ciphertext ]
[ 12 bytes: nonce ]
[ N bytes: ciphertext + 16-byte GCM tag ]
```

Both the implant and the C2 server share a 32-byte pre-shared key derived from the same master key used for configuration encryption.

**Why:** Network inspection tools (IDS, NDR, proxy logs) see only high-entropy binary data. There are no plaintext commands, no identifiable protocol headers, and no clear-text shell output traversing the wire.

**Software mechanism:**
- `pkg/comms/comms.go` implements `SecureConn` with `WriteMessage()` and `ReadMessage()`
- The C2 server (`cmd/c2server/main.go`) wraps accepted `net.Conn` connections in `SecureConn`
- The implant (`cmd/implant/main.go`) wraps the raw BSD socket in `SecureConn`

### 6. Anti-Debug (macOS)

When compiled natively on macOS with CGO enabled, the implant invokes `ptrace(PT_DENY_ATTACH, 0, 0, 0)`. This is a kernel-level mechanism that prevents debuggers (LLDB, GDB, Xcode) from attaching to the process.

**Why:** Slows down reverse engineering and interactive analysis by incident responders.

**Software mechanism:**
- `pkg/evasion/debug_darwin.go` uses a CGO inline C block to call `ptrace`
- A stub (`pkg/evasion/debug_stub.go`) provides a no-op for cross-compilation and non-Darwin builds

### 7. Jittered Beaconing

Reconnect intervals are randomized between 8–15 seconds using `math/rand`. A fixed beacon interval (e.g., every 30 seconds) creates a trivial time-domain signature for detection rules. Jitter smears the signal across the time axis, making time-based correlation less reliable.

**Software mechanism:**
- `time.Sleep(time.Duration(minJitter + rand.Intn(maxJitter-minJitter)) * time.Second)` in `cmd/implant/main.go`

---

## Build

**Cross-compile from Linux (Kali):**
```bash
cd /home/kali/redteam-portfolio
GOOS=darwin GOARCH=arm64 go build -o build/implant_darwin ./cmd/implant
go build -o build/c2server ./cmd/c2server
```

**Native build on macOS:**
```bash
cd redteam-portfolio
go build -o build/implant_darwin ./cmd/implant
codesign -s - -f build/implant_darwin
```

---

## Demo

📹 **[Video Walkthrough](placeholder-link)**

A 2-minute screen recording demonstrating:
1. Ad-hoc signing and execution
2. Disk deletion with running process verification
3. Encrypted C2 command execution
4. Kibana telemetry review (process, network, zero alerts)
5. Disconnect → memory-locked sleep → automatic reconnect
6. tcpdump capture of encrypted C2 traffic

---

## Detection Engineering

Despite the evasion layers, the implant still generates **telemetry**. Defenders should focus on these detection opportunities:

| Telemetry | Detection Logic | Gap |
|-----------|----------------|-----|
| Process creation | Parent process is Terminal + unsigned Mach-O + network connection | Process creation is logged, but no alert fired without behavioral rules |
| Network beacon | Repeated TCP connections to same internal IP on uncommon port | Jitter prevents simple time-based correlation |
| File deletion | File deleted immediately after execution | File event is logged, but binary is already gone |
| mprotect(PROT_NONE) | Rare API call on non-standard memory regions | High false-positive rate; requires tight baselining |
| Memory scan miss | Encrypted/locked pages return faults | Invisible to scanners during sleep |

**Recommended hardening:**
- Restrict unsigned code execution via Gatekeeper + MDM
- Enable Full Disk Access monitoring for unknown processes
- Baseline normal `mprotect` usage and alert on `PROT_NONE` from non-system processes
- Monitor for short-lived TCP connections to internal IPs on non-standard ports

---

## MITRE ATT&CK Mapping

| Technique | ID | Context |
|-----------|-----|---------|
| User Execution | T1204 | User-assisted execution of implant binary |
| Masquerading | T1036 | Binary named `implant_darwin` (could be improved) |
| Encrypted Channel | T1573.002 | AES-256-GCM C2 framing |
| File Deletion | T1070.004 | Self-deletion via `os.Remove` |
| Impair Defenses | T1562.001 | `ptrace(PT_DENY_ATTACH)` to block debuggers |
| Obfuscated Files or Information | T1027 | Runtime config encryption, memory encryption |
| Application Layer Protocol | T1071.001 | Custom TCP C2 protocol over port 8443 |

---

## Disclaimer

This repository contains research and educational code for authorized red team operations, security interviews, and controlled lab environments. Do not use these techniques against systems you do not own or have explicit written permission to test.
