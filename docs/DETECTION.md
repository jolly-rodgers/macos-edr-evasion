# Detection Recommendations (Purple Team)

## Elastic Defend Detections to Enable

- **Malicious Behavior** (process injection, credential access)
- **Memory Threat Detection** (shellcode, memory scanning)
- **Network Connections** (beaconing, unusual outbound)

## Gaps This Exercise Tests

- Memory-only execution without disk artifacts.
- Syscall-based execution bypassing userland hooks.
- Encrypted sleep obfuscating implant presence.

## Recommended Hardening

- Enable Full Disk Access monitoring.
- Restrict unsigned code execution via Gatekeeper.
- Monitor for `mmap` + `MAP_JIT` from unexpected processes.
