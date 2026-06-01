use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::tor::TorHandle;

enum SocksTarget {
    Domain(String, u16),
    Ip(Ipv4Addr, u16),
}

pub async fn run_socks5_server(tor_handle: TorHandle) -> Result<()> {
    let addr = "127.0.0.1:9050";
    let listener = TcpListener::bind(addr).await?;
    log::info!("SOCKS5 proxy listening on {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        let handle = tor_handle.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer, handle).await {
                log::error!("Connection from {} failed: {}", peer, e);
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    tor_handle: TorHandle,
) -> Result<()> {
    log::info!("SOCKS5 connection from {}", peer);

    let mut buf = [0u8; 1024];

    // --- SOCKS5 greeting ---
    let n = stream.read(&mut buf).await?;
    if n < 3 || buf[0] != 0x05 {
        bail!("Invalid SOCKS5 greeting from {}", peer);
    }
    let nmethods = buf[1] as usize;
    if n < 2 + nmethods {
        bail!("Truncated SOCKS5 greeting from {}", peer);
    }
    stream.write_all(&[0x05, 0x00]).await?;

    // --- SOCKS5 request ---
    let n = stream.read(&mut buf).await?;
    if n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
        send_socks5_error(&mut stream, 0x07).await?;
        bail!("Unsupported SOCKS5 command from {}", peer);
    }

    let target = match parse_socks5_addr(&buf[3..n]) {
        Ok(t) => t,
        Err(e) => {
            send_socks5_error(&mut stream, 0x08).await?;
            bail!("{}", e);
        }
    };

    let target_str = match &target {
        SocksTarget::Domain(h, p) => format!("{}:{}", h, p),
        SocksTarget::Ip(ip, p) => format!("{}:{}", ip, p),
    };
    log::info!("SOCKS5 CONNECT {} from {}", target_str, peer);

    // --- Connect through Tor ---
    let connect_result = match &target {
        SocksTarget::Domain(h, p) => tor_handle.client.connect((h.as_str(), *p)).await,
        SocksTarget::Ip(ip, p) => {
            let addr_str = ip.to_string();
            tor_handle.client.connect((addr_str.as_str(), *p)).await
        }
    };
    let mut tor_stream = match connect_result {
        Ok(s) => s,
        Err(e) => {
            send_socks5_error(&mut stream, 0x04).await?;
            bail!("Tor connection to {} failed: {}", target_str, e);
        }
    };

    // --- Send SOCKS5 success response ---
    stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

    // --- Bidirectional copy ---
    match tokio::io::copy_bidirectional(&mut stream, &mut tor_stream).await {
        Ok((a, b)) => log::debug!("SOCKS5 {} relayed {} bytes", peer, a + b),
        Err(e) => log::debug!("SOCKS5 {} relay error: {}", peer, e),
    }

    log::info!("SOCKS5 connection from {} closed", peer);
    Ok(())
}

fn parse_socks5_addr(data: &[u8]) -> Result<SocksTarget> {
    if data.is_empty() {
        bail!("Empty address field");
    }
    let atyp = data[0];
    let rest = &data[1..];

    match atyp {
        0x01 => {
            if rest.len() < 6 {
                bail!("Truncated IPv4 address");
            }
            let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            Ok(SocksTarget::Ip(ip, port))
        }
        0x03 => {
            if rest.is_empty() {
                bail!("Empty domain name");
            }
            let len = rest[0] as usize;
            if rest.len() < 1 + len + 2 {
                bail!("Truncated domain name");
            }
            let domain = String::from_utf8(rest[1..1 + len].to_vec())?;
            let port = u16::from_be_bytes([rest[1 + len], rest[2 + len]]);
            Ok(SocksTarget::Domain(domain, port))
        }
        0x04 => {
            bail!("IPv6 address type not supported");
        }
        _ => bail!("Unknown address type 0x{:02x}", atyp),
    }
}

async fn send_socks5_error(stream: &mut TcpStream, code: u8) -> Result<()> {
    let response = [0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream.write_all(&response).await?;
    Ok(())
}
