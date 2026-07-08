//! quinn 0.11 + h3 0.0.6 plaintext-over-h3 baseline.
//!
//! Mirrors the route surface of
//! `benchmark/baselines/hyper/src/main.rs` -- `/`, `/plaintext`,
//! `/4kb`, `/64kb`, `/1mb`, `/16mb`, `/upload` -- but serves
//! every response over HTTP/3 (QUIC over UDP). The "plaintext"
//! body is the TFB-spec `"Hello, World!"` so the cross-framework
//! comparison against `benchmark/baselines/hyper/` (h1),
//! `benchmark/baselines/quiche/` (h3), and flare's own server
//! lines up on the same payload.
//!
//! TLS: a self-signed Ed25519 certificate is generated at startup
//! (via `rcgen`); the bench client must skip cert verification.
//! That's how every cross-framework HTTP/3 baseline runs --
//! quiche-server, neqo-server, msquic_demo all do the same; it
//! takes the cert-management work out of the bench loop and
//! isolates the QUIC + h3 throughput measurement.
//!
//! Workers: one tokio multi-thread runtime; UDP socket reuse is
//! kernel-side via `SO_REUSEPORT` only when `FLARE_BENCH_WORKERS`
//! is set above 1 -- quinn shares one endpoint per listener so
//! the worker count maps to the tokio runtime size, not to
//! independent UDP fds.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use h3::server::Connection;
use http::{Method, Response, StatusCode};
use quinn::{Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

const BODY: &[u8] = b"Hello, World!";

fn make_payload(n: usize) -> Bytes {
    Bytes::from(vec![b'x'; n])
}

#[derive(Clone)]
struct Payloads {
    b4kb: Bytes,
    b64kb: Bytes,
    b1mb: Bytes,
    b16mb: Bytes,
}

fn build_tls_config() -> rustls::ServerConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .expect("self-signed cert generation");
    let der: Vec<CertificateDer<'static>> = vec![cert.cert.der().clone()];
    let key: PrivateKeyDer<'static> = PrivateKeyDer::try_from(
        cert.key_pair.serialize_der(),
    )
    .expect("Ed25519 key into PrivateKeyDer");
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut cfg = rustls::ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
    ])
    .with_no_client_auth()
    .with_single_cert(der, key)
    .expect("rustls ServerConfig");
    cfg.alpn_protocols = vec![b"h3".to_vec()];
    cfg.max_early_data_size = u32::MAX;
    cfg
}

fn build_quinn_config(tls: rustls::ServerConfig) -> ServerConfig {
    let quic_tls = Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .expect("quinn QuicServerConfig from rustls"),
    );
    let mut cfg = ServerConfig::with_crypto(quic_tls);
    // Mirror the v0.6 throughput-mc shape: large concurrent
    // streams + generous flow control so quinn isn't artificially
    // throttled vs. flare's per-connection settings.
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(1024))
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(8))
        .stream_receive_window(quinn::VarInt::from_u32(8 * 1024 * 1024))
        .receive_window(quinn::VarInt::from_u32(32 * 1024 * 1024));
    cfg.transport_config(Arc::new(transport));
    cfg
}

async fn serve_connection(
    mut conn: Connection<h3_quinn::Connection, Bytes>,
    payloads: Arc<Payloads>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        match conn.accept().await {
            Ok(Some(resolver)) => {
                let payloads = payloads.clone();
                tokio::spawn(async move {
                    if let Ok((req, mut stream)) = resolver.resolve_request().await {
                        let _ = handle_request(req, &mut stream, payloads).await;
                    }
                });
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    Ok(())
}

async fn handle_request<S>(
    req: http::Request<()>,
    stream: &mut h3::server::RequestStream<S, Bytes>,
    payloads: Arc<Payloads>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let (method, path) = (req.method().clone(), req.uri().path().to_owned());
    let resp = match (method, path.as_str()) {
        (Method::GET, "/") | (Method::GET, "/plaintext") => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; charset=utf-8")
            .header("content-length", BODY.len())
            .body(())
            .unwrap(),
        (Method::GET, "/4kb") => fixed_body(&payloads.b4kb),
        (Method::GET, "/64kb") => fixed_body(&payloads.b64kb),
        (Method::GET, "/1mb") => fixed_body(&payloads.b1mb),
        (Method::GET, "/16mb") => fixed_body(&payloads.b16mb),
        (Method::POST, "/upload") => {
            // Drain the request body into a byte count.
            let mut n = 0usize;
            while let Some(chunk) = stream.recv_data().await? {
                n += chunk.remaining();
            }
            let s = n.to_string();
            let r = Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain; charset=utf-8")
                .header("content-length", s.len())
                .body(())
                .unwrap();
            stream.send_response(r).await?;
            stream.send_data(Bytes::from(s)).await?;
            stream.finish().await?;
            return Ok(());
        }
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())
            .unwrap(),
    };

    stream.send_response(resp).await?;
    match path.as_str() {
        "/" | "/plaintext" => {
            stream.send_data(Bytes::from_static(BODY)).await?;
        }
        "/4kb" => stream.send_data(payloads.b4kb.clone()).await?,
        "/64kb" => stream.send_data(payloads.b64kb.clone()).await?,
        "/1mb" => stream.send_data(payloads.b1mb.clone()).await?,
        "/16mb" => stream.send_data(payloads.b16mb.clone()).await?,
        _ => {}
    }
    stream.finish().await?;
    Ok(())
}

fn fixed_body(payload: &Bytes) -> http::Response<()> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .header("content-length", payload.len())
        .body(())
        .unwrap()
}

fn main() -> std::io::Result<()> {
    let workers: usize = env::var("FLARE_BENCH_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    let port: u16 = env::var("FLARE_BENCH_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8443);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?;

    rt.block_on(async move {
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        let tls = build_tls_config();
        let cfg = build_quinn_config(tls);
        let endpoint =
            Endpoint::server(cfg, addr).expect("quinn endpoint bind");
        let payloads = Arc::new(Payloads {
            b4kb: make_payload(4 * 1024),
            b64kb: make_payload(64 * 1024),
            b1mb: make_payload(1024 * 1024),
            b16mb: make_payload(16 * 1024 * 1024),
        });
        eprintln!(
            "quinn-h3 listening on {} (workers={})",
            addr, workers
        );

        while let Some(incoming) = endpoint.accept().await {
            let payloads = payloads.clone();
            tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    let h3_conn = h3_quinn::Connection::new(conn);
                    if let Ok(conn) =
                        Connection::new(h3_conn).await
                    {
                        let _ = serve_connection(conn, payloads).await;
                    }
                }
            });
        }
        Ok::<_, std::io::Error>(())
    })
}
