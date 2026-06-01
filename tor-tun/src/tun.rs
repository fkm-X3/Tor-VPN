use anyhow::Result;
use tokio::io::AsyncReadExt;

use crate::packet;

pub async fn run_tun_reader() -> Result<()> {
    let mut config = tun::Configuration::default();
    config
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .destination((10, 0, 0, 2))
        .mtu(1500)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|c| c.ensure_root_privileges(true));

    let mut dev = tun::create_as_async(&config)?;
    let mut buf = vec![0u8; 65535];
    let mut udp_warned = false;

    log::info!("TUN device created (10.0.0.1/24), listening for packets...");
    log::info!("On Windows, ensure wintun.dll is in the executable directory");
    log::info!("Run with administrator/root privileges for TUN device access");

    loop {
        let n = dev.read(&mut buf).await?;
        if n > 0 {
            process_packet(&buf[..n], &mut udp_warned);
        }
    }
}

fn process_packet(data: &[u8], udp_warned: &mut bool) {
    let ip_header = match packet::IpHeader::parse(data) {
        Some(h) => h,
        None => {
            log::debug!("Failed to parse IP header");
            return;
        }
    };

    match ip_header.protocol {
        packet::PROTOCOL_TCP => {
            if let Some(tcp) = packet::TcpHeader::parse(data, ip_header.ihl as usize) {
                log::debug!(
                    "TCP {}:{} -> {}:{}",
                    ip_header.source,
                    tcp.source_port,
                    ip_header.destination,
                    tcp.dest_port
                );
            }
        }
        packet::PROTOCOL_UDP => {
            if let Some(udp) = packet::UdpHeader::parse(data, ip_header.ihl as usize) {
                if !*udp_warned {
                    log::warn!(
                        "UDP packet detected: {}:{} -> {}:{}",
                        ip_header.source,
                        udp.source_port,
                        ip_header.destination,
                        udp.dest_port
                    );
                    log::warn!("UDP is NOT routed through Tor yet – dropping packet");
                    *udp_warned = true;
                }
            }
        }
        _ => {
            log::debug!("Non-TCP/UDP packet (protocol {})", ip_header.protocol);
        }
    }
}
