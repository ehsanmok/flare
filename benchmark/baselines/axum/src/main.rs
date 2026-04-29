//! axum 0.8 plaintext baseline.
//!
//! Mirrors the route surface of `benchmark/baselines/go_nethttp/main.go`:
//! `/`, `/plaintext`, `/4kb`, `/64kb`, `/1mb`, `/16mb`, `/upload`.
//!
//! Per-request body for `/` and `/plaintext` is the TFB-spec
//! `"Hello, World!"` (13 bytes). axum sits on top of hyper +
//! tokio multi-thread runtime, 4 worker threads by default
//! (env-overridable). axum::serve handles the listener loop;
//! tokio::main proc macro is replaced with explicit Builder
//! so worker count is configurable via env.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Bytes as AxumBytes,
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use bytes::Bytes;
use tokio::net::TcpListener;

const BODY: &[u8] = b"Hello, World!";

#[derive(Clone)]
struct Payloads {
    b4kb: Bytes,
    b64kb: Bytes,
    b1mb: Bytes,
    b16mb: Bytes,
}

async fn plaintext() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        Bytes::from_static(BODY),
    )
        .into_response()
}

async fn download_4kb(State(p): State<Arc<Payloads>>) -> Response {
    download(p.b4kb.clone())
}
async fn download_64kb(State(p): State<Arc<Payloads>>) -> Response {
    download(p.b64kb.clone())
}
async fn download_1mb(State(p): State<Arc<Payloads>>) -> Response {
    download(p.b1mb.clone())
}
async fn download_16mb(State(p): State<Arc<Payloads>>) -> Response {
    download(p.b16mb.clone())
}

fn download(payload: Bytes) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        payload,
    )
        .into_response()
}

async fn upload(body: AxumBytes) -> Response {
    let n = body.len().to_string();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        n,
    )
        .into_response()
}

fn make_payload(n: usize) -> Bytes {
    Bytes::from(vec![b'x'; n])
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
        let payloads = Arc::new(Payloads {
            b4kb: make_payload(4 * 1024),
            b64kb: make_payload(64 * 1024),
            b1mb: make_payload(1024 * 1024),
            b16mb: make_payload(16 * 1024 * 1024),
        });

        let app = Router::new()
            .route("/", get(plaintext))
            .route("/plaintext", get(plaintext))
            .route("/4kb", get(download_4kb))
            .route("/64kb", get(download_64kb))
            .route("/1mb", get(download_1mb))
            .route("/16mb", get(download_16mb))
            .route("/upload", post(upload))
            .with_state(payloads);

        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        let listener = TcpListener::bind(addr).await?;
        eprintln!("axum listening on {} (workers={})", addr, workers);
        axum::serve(listener, app).await
    })
}
