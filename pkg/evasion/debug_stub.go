//go:build !darwin || !cgo

package evasion

// AntiDebug is a no-op stub for non-darwin platforms or when cgo is disabled.
func AntiDebug() {}
