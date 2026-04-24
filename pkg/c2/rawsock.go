package c2

import (
	"fmt"
	"net"
	"strconv"

	"golang.org/x/sys/unix"
)

// RawConn wraps a raw BSD socket file descriptor.
type RawConn struct {
	fd int
}

// DialRaw establishes a TCP connection via direct unix syscalls.
func DialRaw(address string) (*RawConn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(host).To4()
	if ip == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("invalid IPv4: %s", host)
	}

	addr := &unix.SockaddrInet4{
		Port: port,
		Addr: [4]byte{ip[0], ip[1], ip[2], ip[3]},
	}

	if err := unix.Connect(fd, addr); err != nil {
		unix.Close(fd)
		return nil, err
	}

	return &RawConn{fd: fd}, nil
}

// Read waits up to 30 seconds for data, then reads from the socket.
// Detects disconnects via POLLHUP / POLLERR / zero-byte reads.
func (c *RawConn) Read(b []byte) (int, error) {
	fds := []unix.PollFd{{Fd: int32(c.fd), Events: unix.POLLIN}}
	_, err := unix.Poll(fds, 30000) // 30 second timeout
	if err != nil {
		return 0, err
	}

	// Connection closed or error
	if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
		return 0, fmt.Errorf("connection closed")
	}

	// Timeout
	if fds[0].Revents&unix.POLLIN == 0 {
		return 0, fmt.Errorf("read timeout")
	}

	n, err := unix.Read(c.fd, b)
	if n == 0 && err == nil {
		return 0, fmt.Errorf("connection closed")
	}
	return n, err
}

func (c *RawConn) Write(b []byte) (int, error) {
	return unix.Write(c.fd, b)
}

func (c *RawConn) Close() error {
	return unix.Close(c.fd)
}
