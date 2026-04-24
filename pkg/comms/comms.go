package comms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
)

// SecureConn wraps any ReadWriteCloser with AES-256-GCM message framing.
type SecureConn struct {
	rw  io.ReadWriteCloser
	gcm cipher.AEAD
}

// NewSecureConn initializes a SecureConn with a hex-encoded 32-byte key.
func NewSecureConn(rw io.ReadWriteCloser, keyHex string) (*SecureConn, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecureConn{rw: rw, gcm: gcm}, nil
}

// WriteMessage encrypts and sends a discrete message.
func (s *SecureConn) WriteMessage(data []byte) error {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := s.gcm.Seal(nonce, nonce, data, nil)

	// Frame: [4 bytes big-endian length][ciphertext]
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(ciphertext)))

	if _, err := s.rw.Write(header); err != nil {
		return err
	}
	_, err := s.rw.Write(ciphertext)
	return err
}

// ReadMessage receives and decrypts a discrete message.
func (s *SecureConn) ReadMessage() ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(s.rw, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header)
	if length > 16*1024*1024 { // 16MB sanity limit
		return nil, fmt.Errorf("message too large")
	}

	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(s.rw, ciphertext); err != nil {
		return nil, err
	}

	nonceSize := s.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return s.gcm.Open(nil, nonce, ciphertext, nil)
}

// Close closes the underlying connection.
func (s *SecureConn) Close() error {
	return s.rw.Close()
}
