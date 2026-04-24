// Package comms handles C2 channel encryption and framing.
package comms

import (
	"net"
)

// Session wraps an active C2 connection.
type Session struct {
	Conn net.Conn
}

// NewSession initializes a session over an existing connection.
func NewSession(conn net.Conn) *Session {
	return &Session{Conn: conn}
}

// TODO: Add AES encryption, jitter, and heartbeat logic.
