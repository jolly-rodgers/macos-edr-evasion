# macOS EDR Evasion & Custom C2 Portfolio Piece

Target: Elastic Defend on macOS
Attacker: Kali Linux VM

## Structure

- `cmd/c2server/` - C2 server (Kali)
- `cmd/implant/` - macOS implant
- `pkg/evasion/` - Evasion techniques targeting ESF/macOS
- `pkg/comms/` - C2 communication protocols
- `docs/` - Attack chain write-up and detection recommendations
- `scripts/` - Setup and test helpers
- `build/` - Compiled binaries

## JD Coverage

- macOS security
- Linux security (Kali attacker)
- EDR bypass (Elastic Defend)
- Custom tooling & infrastructure
- Golang / C / Python
