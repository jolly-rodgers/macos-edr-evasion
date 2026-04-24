package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"redteam-portfolio/pkg/crypto"
)

func main() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	keyHex := hex.EncodeToString(key)

	if len(os.Args) < 2 {
		fmt.Println("Usage: go run scripts/encrypt_string.go <plaintext>")
		return
	}

	plaintext := os.Args[1]
	encrypted, err := crypto.EncryptString(plaintext, keyHex)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Key:    %s\n", keyHex)
	fmt.Printf("Cipher: %s\n", encrypted)
}
