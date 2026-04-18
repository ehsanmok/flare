// Go stdlib net/http plaintext server — TFB-style reference baseline.
//
// Responds to every request with "Hello, World!\n" as 200 OK
// text/plain; charset=utf-8.
//
// The body is exactly 13 bytes; Content-Length is set explicitly so the
// bytes on the wire match the TFB plaintext workload spec.

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
)

var body = []byte("Hello, World!")

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

func main() {
	// Single-threaded runtime to match our benchmark target.
	runtime.GOMAXPROCS(1)

	addr := "127.0.0.1:8080"
	if v := os.Getenv("FLARE_BENCH_ADDR"); v != "" {
		addr = v
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/plaintext", handler)
	fmt.Printf("go_nethttp listening on %s (GOMAXPROCS=%d)\n", addr, runtime.GOMAXPROCS(0))
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	log.Fatal(server.ListenAndServe())
}
