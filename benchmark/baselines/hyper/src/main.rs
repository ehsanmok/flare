//! hyper 1.x plaintext baseline (HTTP/1.1).
//!
//! Mirrors the route surface of `benchmark/baselines/go_nethttp/main.go`:
//! `/`, `/plaintext`, `/4kb`, `/64kb`, `/1mb`, `/16mb`, `/upload`.
//!
//! Per-request body for `/` and `/plaintext` is the TFB-spec
//! `"Hello, World!"` (13 bytes). Multi-threaded tokio runtime,
//! 4 worker threads by default (env-overridable), one
//! `tokio::net::TcpListener` shared across workers via
//! `Arc<TcpListener>` (hyper 1.x has no built-in SO_REUSEPORT
//! glue; the listener is shared via `Arc` and tokio's
//! per-worker accept). All connections are kept-alive and
//! pipelined per the hyper auto::Builder defaults.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

const BODY: &[u8] = b"Hello, World!";

fn make_payload(n: usize) -> Bytes {
    Bytes::from(vec![b'x'; n])
}

async fn handle(
    req: Request<Incoming>,
    payloads: Arc<Payloads>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();
    let resp = match (req.method(), path) {
        (&Method::GET, "/") | (&Method::GET, "/plaintext") => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; charset=utf-8")
            .header("content-length", BODY.len())
            .body(Full::new(Bytes::from_static(BODY)))
            .unwrap(),
        (&Method::GET, "/4kb") => download(&payloads.b4kb),
        (&Method::GET, "/64kb") => download(&payloads.b64kb),
        (&Method::GET, "/1mb") => download(&payloads.b1mb),
        (&Method::GET, "/16mb") => download(&payloads.b16mb),
        (&Method::POST, "/upload") => {
            let body = req.into_body().collect().await?.to_bytes();
            let n_bytes = body.len();
            let s = n_bytes.to_string();
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain; charset=utf-8")
                .header("content-length", s.len())
                .body(Full::new(Bytes::from(s)))
                .unwrap()
        }
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
            .unwrap(),
    };
    Ok(resp)
}

fn download(payload: &Bytes) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .header("content-length", payload.len())
        .body(Full::new(payload.clone()))
        .unwrap()
}

struct Payloads {
    b4kb: Bytes,
    b64kb: Bytes,
    b1mb: Bytes,
    b16mb: Bytes,
}

fn main() -> std::io::Result<()> {
    let workers: usize = env::var("FLARE_BENCH_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    let port: u16 = env::var("FLARE_BENCH_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?;

    rt.block_on(async move {
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        let listener = TcpListener::bind(addr).await?;
        let payloads = Arc::new(Payloads {
            b4kb: make_payload(4 * 1024),
            b64kb: make_payload(64 * 1024),
            b1mb: make_payload(1024 * 1024),
            b16mb: make_payload(16 * 1024 * 1024),
        });
        eprintln!(
            "hyper listening on {} (workers={})",
            addr, workers
        );

        loop {
            let (stream, _) = listener.accept().await?;
            let payloads = payloads.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| handle(req, payloads.clone()));
                if let Err(_) = http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(io, svc)
                    .await
                {
                    // hyper logs partial-read errors; swallow them so
                    // the per-connection failure mode is invisible to
                    // the wrk2 driver (matches the go_nethttp shape).
                }
            });
        }
    })
}
