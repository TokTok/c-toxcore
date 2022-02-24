package main
import (
        "crypto/tls"
        "encoding/hex"
        "io"
        "log"
        "net"
        "net/http"
        "time"
)

const DEBUG = false

func handleTunneling(w http.ResponseWriter, r *http.Request) {
        log.Printf("opening tunnel to %q", r.Host)
        dest_conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
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
        client_conn, _, err := hijacker.Hijack()
        if err != nil {
                http.Error(w, err.Error(), http.StatusServiceUnavailable)
        }
        log.Printf("starting data transfer")
        go transfer(">", dest_conn, client_conn)
        go transfer("<", client_conn, dest_conn)
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
                if DEBUG {
                        log.Printf("%s %02x", direction, hex.EncodeToString(buf[:n]))
                }
                destination.Write(buf[:n])
        }
}

func main() {
        server := &http.Server{
                Addr: ":8080",
                Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                        if r.Method == http.MethodConnect {
                                handleTunneling(w, r)
                        } else {
                                panic("omg")
                        }
                }),
                // Disable HTTP/2.
                TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
        }
        log.Fatal(server.ListenAndServe())
}
