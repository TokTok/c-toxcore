package main

import (
	"crypto/tls"
	"encoding/hex"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/things-go/go-socks5"
)

const (
	debug                          = false
	httpAddr                       = "127.0.0.1:8080"
	socks5NoAuthAddr               = "127.0.0.1:8081"
	socks5UsernamePasswordAuthAddr = "127.0.0.1:8082"
)

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	log.Printf("opening tunnel to %q", r.Host)
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	log.Printf("responding OK")
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	log.Printf("hijacking HTTP connection")
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	log.Printf("starting data transfer")
	go transfer(">", destConn, clientConn)
	go transfer("<", clientConn, destConn)
}

func transfer(direction string, destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	var buf [2048]byte
	for {
		n, err := source.Read(buf[:])
		if err != nil {
			log.Printf("error: %s", err)
			break
		}
		if debug {
			log.Printf("%s %02x", direction, hex.EncodeToString(buf[:n]))
		}
		destination.Write(buf[:n])
	}
}

func main() {
	log.Printf("starting HTTP proxy server on %s", httpAddr)
	httpServer := &http.Server{
		Addr: httpAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				panic("invalid method, only CONNECT is allowed")
			}
		}),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	log.Printf("starting SOCKS5 no-auth proxy server on %s", socks5NoAuthAddr)
	socks5NoAuthServer := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5 no-auth: ", log.LstdFlags))),
	)

	log.Printf("starting SOCKS5 username/password auth proxy server on %s", socks5UsernamePasswordAuthAddr)
	authenticator := socks5.UserPassAuthenticator{socks5.StaticCredentials{"nurupo": "hunter2"}}
	socks5UsernamePasswordAuthServer := socks5.NewServer(
		socks5.WithAuthMethods([]socks5.Authenticator{authenticator}),
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5 username/password auth: ", log.LstdFlags))),
	)

	go socks5NoAuthServer.ListenAndServe("tcp", socks5NoAuthAddr)
	go socks5UsernamePasswordAuthServer.ListenAndServe("tcp", socks5UsernamePasswordAuthAddr)
	log.Fatal(httpServer.ListenAndServe())
}
