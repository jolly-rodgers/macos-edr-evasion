# Attack Chain: macOS Elastic Defend Evasion

## Objective
Demonstrate sophisticated bypass of Elastic Defend on macOS using a custom implant with encrypted C2, diskless execution, memory protection, and persistence.

## Stages

1. **Initial Access** (Simulated)
   - User-assisted execution of `implant_darwin`.

2. **Persistence**
   - Copies binary to `~/Library/Containers/.cache/systemupdate`.
   - Installs LaunchAgent `com.apple.system.update.plist` with `RunAtLoad` and `StartInterval`.
   - Loads via `launchctl load -w`.

3. **Defense Evasion**
   - Deletes original binary via `os.Remove(os.Args[0])`.
   - Decrypts C2 config at runtime (AES-256-GCM).
   - Sets `ptrace(PT_DENY_ATTACH)` to block debuggers.
   - Uses raw BSD sockets (`socket`, `connect`, `read`, `write`) instead of high-level network APIs.

4. **Memory Protection**
   - Allocates C2 address in an anonymous `mmap` region.
   - Encrypts the region with AES-256-GCM during sleep.
   - Changes memory permissions to `PROT_NONE` via `mprotect`.
   - Restores and decrypts on wake.

5. **Command & Control**
   - Jittered beaconing (8–15s random intervals).
   - All C2 traffic framed with AES-256-GCM encryption.
   - Tasking: shell, file operations, recon.

6. **Documentation**
   - Kibana screenshots of detection vs. clean execution.
   - MITRE ATT&CK mappings per stage.
   - Detection recommendations for the SOC.
