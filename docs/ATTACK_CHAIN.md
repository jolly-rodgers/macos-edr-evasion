# Attack Chain: macOS Elastic Defend Evasion

## Objective
Demonstrate sophisticated bypass of Elastic Defend on macOS using a custom Go implant and C2 infrastructure.

## Stages

1. **Initial Access** (Simulated)
   - User-assisted execution of implant binary on macOS target.

2. **Execution**
   - Implant runs entirely in memory where possible (no disk artifacts).
   - Avoids ESF-heavy APIs.

3. **Evasion**
   - Syscall obfuscation.
   - Encrypted sleep (memory scanning evasion).
   - Legitimate C2 channel blending (HTTPS/DNS).

4. **C2 Communication**
   - Persistent encrypted session to Kali C2 server.
   - Tasking: shell, file operations, recon.

5. **Documentation**
   - Kibana screenshots of detection vs. clean execution.
