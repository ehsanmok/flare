// Go stdlib net/http plaintext server — TFB-style reference baseline.
//
// Responds to every request with "Hello, World!\n" as 200 OK
// text/plain; charset=utf-8.
//
// The body is exactly 13 bytes; Content-Length is set explicitly so the
// bytes on the wire match the TFB plaintext workload spec.
//
// v0.5.0 Step 2 (Track 6.2): adds /4kb, /64kb, /1mb, /16mb
// download routes for the downloads workload, and an /upload
// echo route that reads the request body and replies 200 OK
// with the byte count for the uploads workload. The /slow and
// /churn workloads use /plaintext or / since they don't depend
// on body size.

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
)

var (
	body = []byte("Hello, World!")
	// Pre-allocated download payloads. Generated at startup so
	// the per-request handler is a single Write — measures the
	// server's write throughput, not the allocator's.
	body4kb  = make([]byte, 4*1024)
	body64kb = make([]byte, 64*1024)
	body1mb  = make([]byte, 1024*1024)
	body16mb = make([]byte, 16*1024*1024)
)

func init() {
	for i := range body4kb {
		body4kb[i] = 'x'
	}
	for i := range body64kb {
		body64kb[i] = 'x'
	}
	for i := range body1mb {
		body1mb[i] = 'x'
	}
	for i := range body16mb {
		body16mb[i] = 'x'
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

func mkDownload(payload []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = w.Write(payload)
	}
}

// upload reads the request body and replies 200 OK with a
// short body containing the byte count. Stresses the server's
// body-read path (the corresponding workload exercises 4KB /
// 64KB / 1MB / 16MB request bodies).
func upload(w http.ResponseWriter, r *http.Request) {
	n, err := io.Copy(io.Discard, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	resp := strconv.FormatInt(n, 10)
	w.Header().Set("Content-Length", strconv.Itoa(len(resp)))
	_, _ = w.Write([]byte(resp))
}

func main() {
	// Single-threaded runtime to match our benchmark target.
	runtime.GOMAXPROCS(1)

	addr := "127.0.0.1:8080"
	if v := os.Getenv("FLARE_BENCH_ADDR"); v != "" {
		addr = v
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)
	mux.HandleFunc("/plaintext", handler)
	mux.HandleFunc("/4kb", mkDownload(body4kb))
	mux.HandleFunc("/64kb", mkDownload(body64kb))
	mux.HandleFunc("/1mb", mkDownload(body1mb))
	mux.HandleFunc("/16mb", mkDownload(body16mb))
	mux.HandleFunc("/upload", upload)
	fmt.Printf("go_nethttp listening on %s (GOMAXPROCS=%d)\n", addr, runtime.GOMAXPROCS(0))
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	log.Fatal(server.ListenAndServe())
}
