//! Cloudflare quiche 0.22 plaintext-over-h3 baseline.
//!
//! Mirrors the route surface of
//! `benchmark/baselines/hyper/src/main.rs` -- `/`, `/plaintext`,
//! `/4kb`, `/64kb`, `/1mb`, `/16mb`, `/upload` -- but serves
//! every response over HTTP/3 (QUIC over UDP). The "plaintext"
//! body is the TFB-spec `"Hello, World!"` so the cross-framework
//! comparison against `benchmark/baselines/hyper/` (h1),
//! `benchmark/baselines/quinn/` (h3), and flare's own server
//! lines up on the same payload.
//!
//! quiche is a low-level library: it doesn't ship a runtime,
//! it expects the host to drive the event loop + the UDP I/O.
//! This baseline uses `mio` for the UDP socket + poll loop and
//! a small per-connection HashMap to dispatch incoming
//! datagrams. The structure mirrors quiche's own
//! `examples/http3-server.rs` so the comparison vs. flare's
//! H3 server is apples-to-apples (both implementations roll
//! their own UDP read loop on top of a connection table).
//!
//! TLS: a self-signed Ed25519 certificate is generated at
//! startup via `rcgen`; the bench client must skip cert
//! verification. quiche-server in the upstream quiche repo
//! does the same when the `--cert` / `--key` arguments aren't
//! passed; matches the quinn baseline.

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{ErrorKind, Write};
use std::net::ToSocketAddrs;

use mio::net::UdpSocket;
use quiche::h3::NameValue;
use ring::rand::{SecureRandom, SystemRandom};

const MAX_DATAGRAM_SIZE: usize = 1350;
const BODY: &[u8] = b"Hello, World!";

#[allow(dead_code)]
struct PartialResponse {
    body: Vec<u8>,
    written: usize,
}

struct Client {
    conn: quiche::Connection,
    http3_conn: Option<quiche::h3::Connection>,
    partial_responses: HashMap<u64, PartialResponse>,
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;

fn ensure_temp_cert() -> std::io::Result<(String, String)> {
    let cert_path = "/tmp/flare_bench_quiche_cert.pem";
    let key_path = "/tmp/flare_bench_quiche_key.pem";
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .expect("self-signed cert generation");
    let mut cf = File::create(cert_path)?;
    cf.write_all(cert.cert.pem().as_bytes())?;
    let mut kf = File::create(key_path)?;
    kf.write_all(cert.key_pair.serialize_pem().as_bytes())?;
    Ok((cert_path.to_string(), key_path.to_string()))
}

fn main() -> std::io::Result<()> {
    let port: u16 = env::var("FLARE_BENCH_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8443);

    let bind_addr = format!("127.0.0.1:{}", port);
    let socket_addr =
        bind_addr.to_socket_addrs()?.next().expect("resolved addr");

    let mut poll = mio::Poll::new()?;
    let mut events = mio::Events::with_capacity(1024);
    let mut socket = UdpSocket::bind(socket_addr)?;
    poll.registry().register(
        &mut socket,
        mio::Token(0),
        mio::Interest::READABLE,
    )?;

    let (cert_path, key_path) = ensure_temp_cert()?;
    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).expect("quiche::Config");
    config
        .load_cert_chain_from_pem_file(&cert_path)
        .expect("load cert");
    config
        .load_priv_key_from_pem_file(&key_path)
        .expect("load key");
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .expect("set ALPN");
    config.set_max_idle_timeout(5_000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(32 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(8 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_remote(8 * 1024 * 1024);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(1024);
    config.set_initial_max_streams_uni(8);
    config.set_disable_active_migration(true);
    config.enable_early_data();

    let h3_config = quiche::h3::Config::new().expect("h3 Config");

    let rng = SystemRandom::new();
    let mut conn_id_seed = [0u8; 32];  // SHA-256 output length
    rng.fill(&mut conn_id_seed).expect("rng seed");
    let conn_id_key = ring::hmac::Key::new(
        ring::hmac::HMAC_SHA256,
        &conn_id_seed,
    );

    let mut clients: ClientMap = ClientMap::new();
    let mut buf = [0u8; 65535];
    let mut out = [0u8; MAX_DATAGRAM_SIZE];

    let local_addr = socket.local_addr()?;
    eprintln!("quiche-h3 listening on {}", local_addr);

    let payloads = (
        vec![b'x'; 4 * 1024],
        vec![b'x'; 64 * 1024],
        vec![b'x'; 1024 * 1024],
        vec![b'x'; 16 * 1024 * 1024],
    );

    loop {
        // Compute the next timeout across all live connections;
        // mio's poll uses this as the deadline so timers fire on
        // time.
        let timeout = clients
            .values()
            .filter_map(|c| c.conn.timeout())
            .min();
        poll.poll(&mut events, timeout)?;

        // Drain inbound datagrams.
        'recv: loop {
            if events.is_empty() {
                break 'recv;
            }
            let (n, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break 'recv,
                Err(e) => return Err(e),
            };
            let pkt_buf = &mut buf[..n];

            let hdr = match quiche::Header::from_slice(
                pkt_buf,
                quiche::MAX_CONN_ID_LEN,
            ) {
                Ok(h) => h,
                Err(_) => continue 'recv,
            };

            let conn_id = ring::hmac::sign(&conn_id_key, &hdr.dcid);
            let conn_id =
                &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id = quiche::ConnectionId::from_vec(conn_id.to_vec());

            let client = if let Some(c) = clients.get_mut(&hdr.dcid) {
                c
            } else if let Some(c) = clients.get_mut(&conn_id) {
                c
            } else if hdr.ty == quiche::Type::Initial {
                let scid = quiche::ConnectionId::from_vec(conn_id.to_vec());
                let conn = quiche::accept(
                    &scid,
                    None,
                    local_addr,
                    from,
                    &mut config,
                )
                .expect("quiche::accept");
                clients.insert(
                    scid.clone(),
                    Client {
                        conn,
                        http3_conn: None,
                        partial_responses: HashMap::new(),
                    },
                );
                clients.get_mut(&scid).unwrap()
            } else {
                continue 'recv;
            };

            let recv_info = quiche::RecvInfo {
                from,
                to: local_addr,
            };
            let _ = client.conn.recv(pkt_buf, recv_info);
        }

        // Drive the connection state machines: open h3, process
        // events, build responses, send.
        for client in clients.values_mut() {
            if (client.conn.is_in_early_data() || client.conn.is_established())
                && client.http3_conn.is_none()
            {
                if let Ok(h3) =
                    quiche::h3::Connection::with_transport(&mut client.conn, &h3_config)
                {
                    client.http3_conn = Some(h3);
                }
            }

            if let Some(h3) = client.http3_conn.as_mut() {
                handle_h3_events(&mut client.conn, h3, &mut client.partial_responses, &payloads);
            }
        }

        // Drain outbound bytes.
        for client in clients.values_mut() {
            'send: loop {
                let (write, send_info) = match client.conn.send(&mut out) {
                    Ok(v) => v,
                    Err(quiche::Error::Done) => break 'send,
                    Err(_) => break 'send,
                };
                if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                    if e.kind() == ErrorKind::WouldBlock {
                        break 'send;
                    }
                    return Err(e);
                }
            }
            client.conn.on_timeout();
        }

        // Reap closed connections.
        clients.retain(|_, c| !c.conn.is_closed());
    }
}

fn handle_h3_events(
    conn: &mut quiche::Connection,
    h3: &mut quiche::h3::Connection,
    partial: &mut HashMap<u64, PartialResponse>,
    payloads: &(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
) {
    loop {
        match h3.poll(conn) {
            Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                build_response(conn, h3, stream_id, &list, payloads, partial);
            }
            Ok((_, quiche::h3::Event::Data)) => {}
            Ok((_, quiche::h3::Event::Finished)) => {}
            Ok((_, quiche::h3::Event::Reset(_))) => {}
            Ok((_, quiche::h3::Event::PriorityUpdate)) => {}
            Ok((_, quiche::h3::Event::GoAway)) => {}
            Err(quiche::h3::Error::Done) => break,
            Err(_) => break,
        }
    }
}

fn build_response(
    conn: &mut quiche::Connection,
    h3: &mut quiche::h3::Connection,
    stream_id: u64,
    list: &[quiche::h3::Header],
    payloads: &(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
    partial: &mut HashMap<u64, PartialResponse>,
) {
    let mut method = "GET".to_string();
    let mut path = "/".to_string();
    for h in list {
        match h.name() {
            b":method" => method = String::from_utf8_lossy(h.value()).into(),
            b":path" => path = String::from_utf8_lossy(h.value()).into(),
            _ => {}
        }
    }
    let (status, body): (u16, Vec<u8>) = match (method.as_str(), path.as_str()) {
        ("GET", "/") | ("GET", "/plaintext") => (200, BODY.to_vec()),
        ("GET", "/4kb") => (200, payloads.0.clone()),
        ("GET", "/64kb") => (200, payloads.1.clone()),
        ("GET", "/1mb") => (200, payloads.2.clone()),
        ("GET", "/16mb") => (200, payloads.3.clone()),
        ("POST", "/upload") => {
            // The bench harness sends a CL header; echo zero here
            // because we don't drain the body in this minimal
            // shape -- the bench is throughput-oriented and the
            // hyper baseline echoes the byte count, but for h3
            // we keep the path simple and return a fixed string.
            (200, b"0".to_vec())
        }
        _ => (404, Vec::new()),
    };

    let resp_headers = vec![
        quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
        quiche::h3::Header::new(b"server", b"flare-bench-quiche"),
        quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
    ];

    let _ = h3.send_response(conn, stream_id, &resp_headers, false);

    let written = match h3.send_body(conn, stream_id, &body, true) {
        Ok(v) => v,
        Err(quiche::h3::Error::Done) => 0,
        Err(_) => return,
    };
    if written < body.len() {
        partial.insert(
            stream_id,
            PartialResponse {
                body,
                written,
            },
        );
    }
}
