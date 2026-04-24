//go:build darwin && cgo

package evasion

/*
#include <sys/types.h>
#include <sys/ptrace.h>

void anti_debug() {
	ptrace(PT_DENY_ATTACH, 0, 0, 0);
}
*/
import "C"

// AntiDebug sets PT_DENY_ATTACH to prevent debugger attachment on macOS.
func AntiDebug() {
	C.anti_debug()
}
