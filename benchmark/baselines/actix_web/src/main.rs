//! actix-web 4.x plaintext baseline.
//!
//! Mirrors the route surface of `benchmark/baselines/go_nethttp/main.go`:
//! `/`, `/plaintext`, `/4kb`, `/64kb`, `/1mb`, `/16mb`, `/upload`.
//!
//! Per-request body for `/` and `/plaintext` is the TFB-spec
//! `"Hello, World!"` (13 bytes). actix-web's actor model spawns
//! one worker per `.workers(N)` (default 4 here, env-overridable),
//! each owning its own TCP listener bound to the same port via
//! `SO_REUSEPORT` on Linux — closer to flare's thread-per-core
//! shape than hyper / axum's shared-listener tokio multi-thread.

use std::env;

use actix_web::{
    get, post,
    http::header,
    web, App, HttpResponse, HttpServer, Responder,
};
use bytes::Bytes;

const BODY: &[u8] = b"Hello, World!";

#[get("/")]
async fn root() -> impl Responder {
    plaintext_body()
}

#[get("/plaintext")]
async fn plaintext() -> impl Responder {
    plaintext_body()
}

fn plaintext_body() -> HttpResponse {
    HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/plain; charset=utf-8"))
        .body(BODY)
}

#[derive(Clone)]
struct Payloads {
    b4kb: Bytes,
    b64kb: Bytes,
    b1mb: Bytes,
    b16mb: Bytes,
}

fn make_payload(n: usize) -> Bytes {
    Bytes::from(vec![b'x'; n])
}

#[get("/4kb")]
async fn dl_4kb(p: web::Data<Payloads>) -> impl Responder {
    download(p.b4kb.clone())
}
#[get("/64kb")]
async fn dl_64kb(p: web::Data<Payloads>) -> impl Responder {
    download(p.b64kb.clone())
}
#[get("/1mb")]
async fn dl_1mb(p: web::Data<Payloads>) -> impl Responder {
    download(p.b1mb.clone())
}
#[get("/16mb")]
async fn dl_16mb(p: web::Data<Payloads>) -> impl Responder {
    download(p.b16mb.clone())
}

fn download(payload: Bytes) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "application/octet-stream"))
        .body(payload)
}

#[post("/upload")]
async fn upload(body: web::Bytes) -> impl Responder {
    let n = body.len().to_string();
    HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/plain; charset=utf-8"))
        .body(n)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let workers: usize = env::var("FLARE_BENCH_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    let port: u16 = env::var("FLARE_BENCH_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);

    let payloads = web::Data::new(Payloads {
        b4kb: make_payload(4 * 1024),
        b64kb: make_payload(64 * 1024),
        b1mb: make_payload(1024 * 1024),
        b16mb: make_payload(16 * 1024 * 1024),
    });

    eprintln!("actix-web listening on 127.0.0.1:{} (workers={})", port, workers);
    HttpServer::new(move || {
        App::new()
            .app_data(payloads.clone())
            .service(root)
            .service(plaintext)
            .service(dl_4kb)
            .service(dl_64kb)
            .service(dl_1mb)
            .service(dl_16mb)
            .service(upload)
    })
    .workers(workers)
    .bind(("127.0.0.1", port))?
    .run()
    .await
}
