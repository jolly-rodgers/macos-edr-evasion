#!/usr/bin/env python3
"""
Mac demo teleprompter + auto-typer.
Run this in a Terminal window on your Mac. It will print narration for you to read
and automatically type commands into the active Terminal window via AppleScript.

On first run, macOS may ask you to grant Terminal accessibility permissions.
Go to System Settings > Privacy & Security > Accessibility and allow Terminal.
"""

import subprocess
import time
import sys


def narrate(text):
    """Print narration text and wait for Enter."""
    print("\n" + "=" * 70)
    print(text)
    print("=" * 70)
    input("\n>> PRESS ENTER TO CONTINUE <<")


def type_command(cmd, delay=0.05):
    """Type a command into the frontmost Terminal window using AppleScript."""
    # Escape backslashes and double quotes for AppleScript
    safe = cmd.replace("\\", "\\\\").replace('"', '\\"')

    script = f'''
    tell application "Terminal"
        activate
    end tell
    delay 0.3
    tell application "System Events"
        keystroke "{safe}"
        keystroke return
    end tell
    '''
    subprocess.run(["osascript", "-e", script])


def main():
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║  DEMO TYPER / TELEPROMPTER                                           ║
║  Read the narration aloud, then press Enter to auto-type commands   ║
╚══════════════════════════════════════════════════════════════════════╝
""")

    # ── PHASE 1: Setup ────────────────────────────────────────────────
    narrate(
        "PHASE 1 — Setup.\n"
        "First, I will navigate to the implant directory and ad-hoc sign the binary "
        "so macOS does not block the network connection."
    )
    type_command("cd ~/Documents/Security\\ Engineer\\ Portfolio/c2-mutation-engine/")

    narrate(
        "Ad-hoc signing the binary with an empty identity. "
        "This prevents the macOS firewall from prompting the user during execution."
    )
    type_command("codesign -s - -f ./implant_darwin")

    # ── PHASE 2: Execution ────────────────────────────────────────────
    narrate(
        "PHASE 2 — Execution.\n"
        "Now I will run the implant. Watch the terminal output."
    )
    type_command("./implant_darwin")

    narrate(
        "The implant has started, removed itself from disk, and connected to the C2 server.\n"
        "Notice there is no file left on disk, yet the process is still running in memory.\n"
        "\n"
        "ACTION: Switch to your Kali VM and show the C2 session, then come back here and press Enter."
    )

    # ── PHASE 3: Verification (new terminal tab recommended) ──────────
    narrate(
        "PHASE 3 — Diskless Verification.\n"
        "Open a NEW terminal tab on your Mac for the verification commands, "
        "then press Enter."
    )
    type_command("ls -la")

    narrate(
        "The binary is gone. Now I will show that the process is still active in memory."
    )
    type_command("ps aux | grep -i implant")

    narrate(
        "The process is running with no on-disk artifact.\n"
        "Next, I will check the active network connection to the Kali C2 server."
    )
    type_command("lsof -i :8443")

    # ── PHASE 4: Kibana telemetry ─────────────────────────────────────
    narrate(
        "PHASE 4 — EDR Telemetry Review.\n"
        "Switch to your browser showing Kibana.\n"
        "Show: Security > Hosts > Events with process and network events.\n"
        "Then show: Security > Alerts — zero behavioral alerts generated.\n"
        "\n"
        "ACTION: Show Kibana screens, then return here and press Enter."
    )

    # ── PHASE 5: Disconnect / Reconnect ───────────────────────────────
    narrate(
        "PHASE 5 — Resilience.\n"
        "I will now kill the C2 server on Kali. The implant will detect the loss, "
        "encrypt its C2 address in memory, lock the page with mprotect, and jitter-sleep.\n"
        "\n"
        "ACTION: Kill the C2 server on Kali, then press Enter."
    )

    narrate(
        "Watch the Mac terminal. The implant prints 'Connection lost', then sleeps with the memory locked.\n"
        "After the jitter interval, it decrypts the buffer and reconnects automatically.\n"
        "\n"
        "ACTION: Restart the C2 server on Kali, wait for reconnect, then press Enter."
    )

    # ── PHASE 6: Encrypted traffic ────────────────────────────────────
    narrate(
        "PHASE 6 — Encrypted C2 Channel.\n"
        "Open a terminal on Kali and run the tcpdump command to prove the traffic is encrypted.\n"
        "Then press Enter here when ready."
    )
    type_command(
        "sudo tcpdump -i any -A host 192.168.1.162 and port 8443 -c 10",
        delay=0.02
    )

    narrate(
        "The tcpdump output shows binary noise — no plaintext commands or responses.\n"
        "All C2 traffic is framed with AES-256-GCM encryption.\n"
        "\n"
        "DEMO COMPLETE. Thank you for watching."
    )

    print("\n" + "=" * 70)
    print("END OF DEMO SCRIPT")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDemo script interrupted.")
        sys.exit(0)
