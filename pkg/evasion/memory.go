package evasion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// SecureBuffer holds sensitive data in an anonymous mmap region.
type SecureBuffer struct {
	data []byte
}

// NewSecureBuffer allocates a page-aligned anonymous mmap.
func NewSecureBuffer(size int) (*SecureBuffer, error) {
	pageSize := unix.Getpagesize()
	allocSize := size
	if allocSize%pageSize != 0 {
		allocSize = ((allocSize / pageSize) + 1) * pageSize
	}

	b, err := unix.Mmap(-1, 0, allocSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	return &SecureBuffer{data: b}, nil
}

// Write copies data into the buffer and zeroes the remainder.
func (s *SecureBuffer) Write(p []byte) {
	n := copy(s.data, p)
	for i := n; i < len(s.data); i++ {
		s.data[i] = 0
	}
}

// String returns the buffer contents as a trimmed string.
func (s *SecureBuffer) String() string {
	return strings.TrimRight(string(s.data), "\x00")
}

// Lock encrypts the buffer with AES-256-GCM and marks memory PROT_NONE.
func (s *SecureBuffer) Lock(key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, s.data, nil)
	if len(ciphertext) > len(s.data) {
		return fmt.Errorf("encrypted data exceeds buffer")
	}
	copy(s.data, ciphertext)

	return unix.Mprotect(s.data, unix.PROT_NONE)
}

// Unlock marks memory RW again and decrypts the buffer.
func (s *SecureBuffer) Unlock(key []byte) error {
	if err := unix.Mprotect(s.data, unix.PROT_READ|unix.PROT_WRITE); err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonceSize := gcm.NonceSize()
	if len(s.data) < nonceSize {
		return fmt.Errorf("buffer too small")
	}

	nonce, ciphertext := s.data[:nonceSize], s.data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}
	copy(s.data, plaintext)
	return nil
}

// Sleep locks the buffer for a duration, then unlocks it.
func (s *SecureBuffer) Sleep(key []byte, duration time.Duration) error {
	if err := s.Lock(key); err != nil {
		return err
	}
	time.Sleep(duration)
	return s.Unlock(key)
}

// Wipe zeros and unmaps the buffer.
func (s *SecureBuffer) Wipe() error {
	for i := range s.data {
		s.data[i] = 0
	}
	return unix.Munmap(s.data)
}

// DeriveKey creates a 32-byte AES key from arbitrary input.
func DeriveKey(input []byte) []byte {
	hash := sha256.Sum256(input)
	return hash[:]
}
