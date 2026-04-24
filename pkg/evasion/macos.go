// Package evasion provides macOS-specific tradecraft to evade Elastic Defend / ESF.
package evasion

import (
	"fmt"
	"runtime"
)

// CheckPlatform ensures we are running on darwin.
func CheckPlatform() error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("evasion/macos: target OS is %s, expected darwin", runtime.GOOS)
	}
	return nil
}

// TODO: Implement memory encryption, syscall obfuscation, and ESF-aware execution.
