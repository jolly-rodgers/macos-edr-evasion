#!/usr/bin/env python3
"""
Mac demo auto-typer. Press Enter to advance through phases.
Each phase automatically types the relevant terminal command(s).
"""

import subprocess
import sys
import time

PHASES = [
    (
        "Setup",
        [
            "cd ~/Documents/Security\\ Engineer\\ Portfolio/c2-mutation-engine/",
            "codesign -s - -f ./implant_darwin",
        ],
    ),
    (
        "Execution",
        [
            "./implant_darwin",
        ],
    ),
    (
        "Diskless Verification",
        [
            "ls -la",
            "ps aux | grep -i implant",
            "lsof -i :8443",
        ],
    ),
    (
        "Encrypted Traffic Capture",
        [
            "sudo tcpdump -i any -A host 192.168.1.162 and port 8443 -c 10",
        ],
    ),
]


def type_command(cmd):
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
    print("=" * 60)
    print("  DEMO AUTO-TYPER")
    print("  Press Enter to type each phase's commands")
    print("=" * 60)

    for title, commands in PHASES:
        print(f"\n[ PHASE: {title} ]")
        for cmd in commands:
            print(f"  > {cmd}")
        input("\n>> PRESS ENTER <<")

        for idx, cmd in enumerate(commands):
            type_command(cmd)
            if idx < len(commands) - 1:
                time.sleep(1.5)

    print("\n" + "=" * 60)
    print("  DEMO COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(0)
