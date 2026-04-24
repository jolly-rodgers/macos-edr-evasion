#!/usr/bin/env python3
"""Demo slideshow teleprompter for macOS terminal."""

import os
import sys

SLIDES = [
    (
        "MACOS EDR EVASION DEMO",
        "Custom implant vs Elastic Defend\n"
        "Techniques: diskless execution, memory encryption, raw sockets, AES-GCM C2"
    ),
    (
        "PHASE 1 — Setup",
        "Navigate to the implant directory and ad-hoc sign the binary.\n"
        "This prevents macOS from blocking the outbound connection."
    ),
    (
        "PHASE 2 — Execution",
        "Run the implant and watch the terminal output.\n"
        "It will delete itself from disk while keeping the process in memory."
    ),
    (
        "PHASE 3 — Diskless Verification",
        "Check the directory: the binary is gone.\n"
        "Check the process list: the implant is still running.\n"
        "Check the network: an active C2 connection exists."
    ),
    (
        "PHASE 4 — Kibana Telemetry",
        "In Elastic Defend:\n"
        "  - Process event shows implant_darwin executed\n"
        "  - Network event shows beacon to 192.168.1.165:8443\n"
        "  - Alerts page shows ZERO behavioral alerts"
    ),
    (
        "PHASE 5 — Resilience",
        "Kill the C2 server. The implant detects the loss, encrypts its\n"
        "C2 address in memory, locks the page with mprotect, and sleeps.\n"
        "After a jittered interval, it decrypts and reconnects automatically."
    ),
    (
        "PHASE 6 — Encrypted C2 Channel",
        "Capture traffic with tcpdump.\n"
        "The payload is binary noise — no plaintext commands or responses.\n"
        "All C2 traffic is framed with AES-256-GCM encryption."
    ),
    (
        "DEMO COMPLETE",
        "Summary:\n"
        "  - No disk artifact after execution\n"
        "  - Memory-locked sleep defeats string scans\n"
        "  - Raw BSD sockets bypass libSystem hooks\n"
        "  - Zero Elastic Defend alerts generated\n\n"
        "Thank you for watching."
    ),
]


def clear():
    os.system("clear")


def show_slide(number, title, body):
    clear()
    print("=" * 70)
    print(f"  SLIDE {number}/{len(SLIDES)}: {title}")
    print("=" * 70)
    print()
    print(body)
    print()
    print("-" * 70)


def main():
    for idx, (title, body) in enumerate(SLIDES, 1):
        show_slide(idx, title, body)
        input("[PRESS ENTER TO CONTINUE]")
    clear()
    print("END OF SLIDESHOW")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(0)
