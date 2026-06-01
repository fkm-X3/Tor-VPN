use rand::Rng;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::windows::io::AsRawSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use crate::packet;

const UDP_TIMEOUT: Duration = Duration::from_secs(60);

struct NatEntry {
    client_ip: Ipv4Addr,
    client_port: u16,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    socket: UdpSocket,
    last_used: Instant,
}

pub struct UdpForwarder {
    entries: HashMap<u16, NatEntry>,
    if_index: u32,
    shutdown: Arc<AtomicBool>,
}

impl UdpForwarder {
    pub fn new(
        if_index: u32,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            entries: HashMap::new(),
            if_index,
            shutdown,
        }
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn handle_packet(
        &mut self,
        data: &[u8],
        tun_ip: Ipv4Addr,
        tor_outbound_ip: Ipv4Addr,
    ) {
        let Some(pkt) = packet::classify_packet(data) else { return };
        let packet::TransportInfo::Udp(ref udp) = pkt.transport else { return };

        let src_ip = pkt.ip_header.src_ip;
        let dst_ip = pkt.ip_header.dst_ip;
        let src_port = udp.src_port;
        let dst_port = udp.dst_port;

        if src_ip.is_loopback() || dst_ip.is_loopback() { return; }
        if src_ip == tun_ip || dst_ip == tun_ip { return; }
        if src_ip == tor_outbound_ip { return; }

        self.forward(src_ip, src_port, dst_ip, dst_port, &pkt.payload);
    }

    pub fn poll_responses(&mut self, tun_writer: &dyn Fn(&[u8])) {
        let mut responses = Vec::new();
        let mut timed_out = Vec::new();

        for (&nat_port, entry) in &self.entries {
            if entry.last_used.elapsed() > UDP_TIMEOUT {
                timed_out.push(nat_port);
                continue;
            }
            let mut buf = [0u8; 65535];
            loop {
                match entry.socket.peek_from(&mut buf) {
                    Ok((n, _)) => {
                        // We peeked it, now actually read to consume
                        let mut recv_buf = vec![0u8; n];
                        match entry.socket.recv_from(&mut recv_buf) {
                            Ok((_, SocketAddr::V4(_))) => {
                                // Build response IP packet
                                let mut ip_pkt = packet::build_ipv4_packet(
                                    &recv_buf,
                                    entry.dest_ip,  // source: the original destination (server)
                                    entry.client_ip, // dest: original client
                                    17, 64, rand::thread_rng().gen(),
                                );
                                // Fix UDP ports in the packet
                                if ip_pkt.len() >= 28 {
                                    let udp_start = 20;
                                    // src port should be dest_port (server's port)
                                    ip_pkt[udp_start..udp_start+2]
                                        .copy_from_slice(&entry.dest_port.to_be_bytes());
                                    // dst port should be client_port
                                    ip_pkt[udp_start+2..udp_start+4]
                                        .copy_from_slice(&entry.client_port.to_be_bytes());
                                    // Zero out checksum (won't be verified)
                                    for b in ip_pkt[udp_start+6..udp_start+8].iter_mut() {
                                        *b = 0;
                                    }
                                }
                                responses.push(ip_pkt);
                            }
                            Ok(_) => continue,
                            Err(_) => break,
                        }
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(_) => break,
                }
            }
        }

        // Remove timed out entries
        for port in timed_out {
            self.entries.remove(&port);
            debug!("UDP NAT timeout: port {port}");
        }

        // Write responses to TUN
        for pkt in responses {
            tun_writer(&pkt);
        }
    }

    fn forward(
        &mut self,
        client_ip: Ipv4Addr,
        client_port: u16,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        payload: &[u8],
    ) {
        let nat_port = self.find_or_create_nat(client_ip, client_port, dest_ip, dest_port);

        if let Some(nat_port) = nat_port {
            if let Some(entry) = self.entries.get(&nat_port) {
                let target = SocketAddr::from((dest_ip, dest_port));
                if let Err(e) = entry.socket.send_to(payload, target) {
                    warn!("UDP forward error: {e}");
                }
            }
        }
    }

    fn find_or_create_nat(
        &mut self,
        client_ip: Ipv4Addr,
        client_port: u16,
        dest_ip: Ipv4Addr,
        dest_port: u16,
    ) -> Option<u16> {
        for (&np, entry) in &self.entries {
            if entry.client_ip == client_ip
                && entry.client_port == client_port
                && entry.dest_ip == dest_ip
                && entry.dest_port == dest_port
            {
                return Some(np);
            }
        }

        let socket = match self.create_udp_socket() {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to create UDP NAT socket: {e}");
                return None;
            }
        };
        let local_addr = socket.local_addr().ok()?;
        let nat_port = match local_addr {
            SocketAddr::V4(a) => a.port(),
            _ => return None,
        };

        self.entries.insert(nat_port, NatEntry {
            client_ip,
            client_port,
            dest_ip,
            dest_port,
            socket,
            last_used: Instant::now(),
        });

        debug!("UDP NAT: {client_ip}:{client_port} -> {dest_ip}:{dest_port} via {nat_port}");
        Some(nat_port)
    }

    fn create_udp_socket(&self) -> std::io::Result<UdpSocket> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        set_unicast_if(&socket, self.if_index)?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        socket.bind(&SocketAddr::from(([0u8, 0, 0, 0], 0)).into())?;
        Ok(socket.into())
    }

    pub fn cleanup(&mut self) {
        self.entries.retain(|_, e| e.last_used.elapsed() < UDP_TIMEOUT);
    }
}

impl Drop for UdpForwarder {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

fn set_unicast_if(socket: &Socket, if_index: u32) -> std::io::Result<()> {
    use windows_sys::Win32::Networking::WinSock::{setsockopt, SOL_IP};

    const IP_UNICAST_IF: i32 = 31;
    let raw_fd = socket.as_raw_socket();
    let idx = if_index.to_be();
    let ret = unsafe {
        setsockopt(
            raw_fd as usize,
            SOL_IP as i32,
            IP_UNICAST_IF,
            &idx as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        )
    };
    if ret == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}
