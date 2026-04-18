// fasthttp plaintext server — zero-alloc Go HTTP server as a stretch
// comparison target.
//
// Responds to /plaintext with exactly "Hello, World!" (13 bytes) and
// text/plain; charset=utf-8, matching the TFB plaintext workload spec.

package main

import (
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/valyala/fasthttp"
)

var body = []byte("Hello, World!")

func handler(ctx *fasthttp.RequestCtx) {
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("text/plain; charset=utf-8")
	ctx.SetBody(body)
}

func main() {
	runtime.GOMAXPROCS(1)

	addr := "127.0.0.1:8080"
	if v := os.Getenv("FLARE_BENCH_ADDR"); v != "" {
		addr = v
	}

	s := &fasthttp.Server{
		Handler:           handler,
		DisableKeepalive:  false,
		// These match our config; fasthttp has aggressive defaults.
		ReduceMemoryUsage: false,
	}
	fmt.Printf("go_fasthttp listening on %s (GOMAXPROCS=%d)\n", addr, runtime.GOMAXPROCS(0))
	log.Fatal(s.ListenAndServe(addr))
}
