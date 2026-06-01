use anyhow::Result;
use crossbeam::channel::{bounded, Receiver, Sender};
use rand::Rng;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::os::windows::io::{AsRawSocket, IntoRawSocket, FromRawSocket};
use std::thread;
use std::time::Duration;
use tracing::{debug, warn};

use crate::packet;

const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;
const TCP_PSH: u8 = 0x08;
const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;
const TCP_WINDOW: u16 = 65535;

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct FlowKey {
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
}

impl FlowKey {
    fn from_parts(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Self {
        Self {
            src_ip: u32::from(src_ip),
            src_port,
            dst_ip: u32::from(dst_ip),
            dst_port,
        }
    }
}

struct TcpSession {
    client_seq: u32,
    our_seq: u32,
    app_to_proxy: Sender<Vec<u8>>,
    proxy_to_app: Receiver<Vec<u8>>,
    close_signal: Sender<()>,
    relay_handle: Option<thread::JoinHandle<()>>,
    pending_output: Vec<Vec<u8>>,
    fin_sent: bool,
    fin_received: bool,
    pending_close: bool,
}

pub struct TcpProxy {
    sessions: HashMap<FlowKey, TcpSession>,
    physical_if_index: u32,
    socks_host: String,
    socks_port: u16,
    tor_outbound_ip: Ipv4Addr,
    tun_ip: Ipv4Addr,
}

impl TcpProxy {
    pub fn new(
        physical_if_index: u32,
        socks_host: String,
        socks_port: u16,
        tor_outbound_ip: Ipv4Addr,
        tun_ip: Ipv4Addr,
    ) -> Self {
        Self {
            sessions: HashMap::new(),
            physical_if_index,
            socks_host,
            socks_port,
            tor_outbound_ip,
            tun_ip,
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn handle_packet(&mut self, data: &[u8]) {
        let Some(pkt) = packet::classify_packet(data) else { return };
        let packet::TransportInfo::Tcp(ref tcp) = pkt.transport else { return };

        let src_ip = pkt.ip_header.src_ip;
        let dst_ip = pkt.ip_header.dst_ip;
        let src_port = tcp.src_port;
        let dst_port = tcp.dst_port;
        let flags = tcp.data_offset_reserved_flags as u8;
        let seq = tcp.sequence_number;
        let payload = &pkt.payload;

        // Bypass checks
        if dst_ip == self.tun_ip || src_ip == self.tun_ip { return; }
        if src_ip.is_loopback() || dst_ip.is_loopback() { return; }
        if src_ip == self.tor_outbound_ip { return; }

        let key = FlowKey::from_parts(src_ip, src_port, dst_ip, dst_port);

        if packet::syn_flag(flags as u16) && !packet::ack_flag(flags as u16) {
            if self.sessions.contains_key(&key) { return; }
            debug!("New TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}");
            self.handle_new_connection(&key, &pkt, tcp);
            return;
        }

        if let Some(session) = self.sessions.get_mut(&key) {
            let fin_rcvd = packet::fin_flag(flags as u16);
            let rst_rcvd = packet::rst_flag(flags as u16);

            if rst_rcvd {
                debug!("RST received, closing session");
                session.pending_close = true;
                let _ = session.close_signal.try_send(());
                return;
            }

            if fin_rcvd {
                debug!("FIN received");
                session.fin_received = true;
                session.pending_close = true;
                // Queue our FIN+ACK for writing by process_responses
                session.pending_output.push(build_tcp_ip_packet(
                    session.our_seq, session.client_seq,
                    TCP_FIN | TCP_ACK,
                    pkt.ip_header.dst_ip, pkt.ip_header.src_ip,
                    tcp.dst_port, tcp.src_port, &[],
                ));
                session.fin_sent = true;
                session.our_seq = session.our_seq.wrapping_add(1);
                return;
            }

            if !payload.is_empty() {
                let payload_owned = payload.to_vec();
                let data_len = payload_owned.len() as u32;
                session.client_seq = seq.wrapping_add(data_len);
                if let Err(e) = session.app_to_proxy.try_send(payload_owned) {
                    warn!("Channel send error: {e}");
                }
            }
        }
    }

    pub fn process_responses(&mut self, tun_writer: &dyn Fn(&[u8])) {
        let mut to_remove = Vec::new();

        let keys: Vec<FlowKey> = self.sessions.keys().cloned().collect();
        for key in &keys {
            let session = match self.sessions.get_mut(key) {
                Some(s) => s,
                None => continue,
            };

            // Write any queued output segments (e.g. FIN+ACK)
            for seg in session.pending_output.drain(..) {
                tun_writer(&seg);
            }

            if session.pending_close {
                to_remove.push(key.clone());
                continue;
            }

            // Drain proxy responses and send to app via TUN
            let mut ack_needed = false;
            while let Ok(msg) = session.proxy_to_app.try_recv() {
                let src_ip = Ipv4Addr::from(key.dst_ip);
                let dst_ip = Ipv4Addr::from(key.src_ip);
                let src_port = key.dst_port;
                let dst_port = key.src_port;

                let seg = build_tcp_ip_packet(
                    session.our_seq, session.client_seq,
                    TCP_PSH | TCP_ACK,
                    src_ip, dst_ip, src_port, dst_port, &msg,
                );
                session.our_seq = session.our_seq.wrapping_add(msg.len() as u32);
                tun_writer(&seg);
                ack_needed = true;
            }

            if ack_needed {
                let src_ip = Ipv4Addr::from(key.dst_ip);
                let dst_ip = Ipv4Addr::from(key.src_ip);
                let seg = build_tcp_ip_packet(
                    session.our_seq, session.client_seq,
                    TCP_ACK, src_ip, dst_ip, key.dst_port, key.src_port, &[],
                );
                tun_writer(&seg);
            }
        }

        for key in to_remove {
            if let Some(session) = self.sessions.remove(&key) {
                let _ = session.close_signal.try_send(());
                if let Some(h) = session.relay_handle {
                    let _ = h.join();
                }
            }
        }
    }

    fn handle_new_connection(&mut self, key: &FlowKey, pkt: &packet::PacketInfo, tcp: &packet::TcpHeader) {
        let our_isn = rand::thread_rng().gen::<u32>();
        let our_seq_initial = our_isn.wrapping_add(1);

        // Send SYN-ACK
        let syn_ack = build_tcp_ip_packet(
            our_isn, tcp.sequence_number.wrapping_add(1),
            TCP_SYN | TCP_ACK,
            pkt.ip_header.dst_ip, pkt.ip_header.src_ip,
            tcp.dst_port, tcp.src_port, &[],
        );

        let (app_to_proxy_tx, app_to_proxy_rx) = bounded::<Vec<u8>>(256);
        let (proxy_to_app_tx, proxy_to_app_rx) = bounded::<Vec<u8>>(256);
        let (close_tx, close_rx) = bounded::<()>(1);

        let socks_host = self.socks_host.clone();
        let socks_port = self.socks_port;
        let target = SocketAddr::V4(SocketAddrV4::new(pkt.ip_header.dst_ip, tcp.dst_port));
        let if_index = self.physical_if_index;

        let relay_handle = thread::Builder::new()
            .name(format!("relay-{}:{}", key.src_ip, key.src_port))
            .spawn(move || {
                // Connect to SOCKS5
                let stream = match connect_socks5(&socks_host, socks_port, target, if_index) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("SOCKS5 connect failed: {e}");
                        return;
                    }
                };
                let close = close_rx;

                // Single relay thread: poll both SOCKS5 and app channel
                let mut buf = [0u8; 65535];
                stream.set_read_timeout(Some(Duration::from_millis(50))).ok();

                loop {
                    // Check if we should close
                    if close.try_recv().is_ok() {
                        // Drain remaining data from app
                        while let Ok(data) = app_to_proxy_rx.try_recv() {
                            let _ = (&stream).write_all(&data);
                        }
                        break;
                    }

                    // Send app data to SOCKS5
                    while let Ok(data) = app_to_proxy_rx.try_recv() {
                        if let Err(e) = (&stream).write_all(&data) {
                            warn!("SOCKS5 write error: {e}");
                            return;
                        }
                        (&stream).flush().ok();
                    }

                    // Read response from SOCKS5
                    match (&stream).read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if proxy_to_app_tx.send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                        Err(ref e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut => {}
                        Err(_) => break,
                    }
                }
            })
            .unwrap();

        let mut session = TcpSession {
            client_seq: tcp.sequence_number.wrapping_add(1),
            our_seq: our_seq_initial,
            app_to_proxy: app_to_proxy_tx,
            proxy_to_app: proxy_to_app_rx,
            close_signal: close_tx,
            relay_handle: Some(relay_handle),
            pending_output: Vec::new(),
            fin_sent: false,
            fin_received: false,
            pending_close: false,
        };
        session.pending_output.push(syn_ack);
        self.sessions.insert(key.clone(), session);
    }
}

fn connect_socks5(host: &str, port: u16, target: SocketAddr, if_index: u32) -> Result<TcpStream> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    set_unicast_if(&socket, if_index)?;

    let proxy_addr: SocketAddr = format!("{host}:{port}").parse()?;
    socket.connect(&proxy_addr.into())?;
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    socket.set_write_timeout(Some(Duration::from_secs(30)))?;

    let stream = unsafe { TcpStream::from_raw_socket(socket.into_raw_socket()) };
    socks5_handshake(&stream, target)?;
    Ok(stream)
}

fn socks5_handshake(mut stream: &TcpStream, target: SocketAddr) -> Result<()> {
    let mut buf = [0u8; 512];

    // Method negotiation
    {
        let mut w = stream;
        w.write_all(&[5, 1, 0])?;
        w.read_exact(&mut buf[..2])?;
        if buf[0] != 5 || buf[1] != 0 {
            anyhow::bail!("SOCKS5: server rejected no-auth");
        }
    }

    // CONNECT
    let addr_bytes: Vec<u8> = match target {
        SocketAddr::V4(a) => {
            let mut v = Vec::with_capacity(10);
            v.extend_from_slice(&[5, 1, 0, 1]);
            v.extend_from_slice(&a.ip().octets());
            v.extend_from_slice(&a.port().to_be_bytes());
            v
        }
        SocketAddr::V6(a) => {
            let mut v = Vec::with_capacity(22);
            v.extend_from_slice(&[5, 1, 0, 4]);
            v.extend_from_slice(&a.ip().octets());
            v.extend_from_slice(&a.port().to_be_bytes());
            v
        }
    };

    {
        let mut w = stream;
        w.write_all(&addr_bytes)?;
        w.read_exact(&mut buf[..4])?;
    }

    if buf[0] != 5 || buf[1] != 0 {
        anyhow::bail!("SOCKS5: CONNECT failed with code {}", buf[1]);
    }

    // Skip remaining response (BND address + port)
    let addr_type = buf[3];
    match addr_type {
        1 => {
            let mut skip = vec![0u8; 6]; // IPv4 addr (4) + port (2)
            stream.read_exact(&mut skip)?;
        }
        4 => {
            let mut skip = vec![0u8; 18]; // IPv6 addr (16) + port (2)
            stream.read_exact(&mut skip)?;
        }
        3 => {
            let mut dlen = [0u8; 1];
            stream.read_exact(&mut dlen)?;
            let mut skip = vec![0u8; dlen[0] as usize + 2]; // domain + port
            stream.read_exact(&mut skip)?;
        }
        _ => anyhow::bail!("SOCKS5: unknown address type {addr_type}"),
    }

    Ok(())
}

fn set_unicast_if(socket: &socket2::Socket, if_index: u32) -> std::io::Result<()> {
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

fn build_tcp_ip_packet(
    seq: u32, ack: u32, flags: u8,
    src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
    src_port: u16, dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_hdr_len: usize = 20;
    let total_len = 20 + tcp_hdr_len + payload.len();
    let mut buf = vec![0u8; total_len];

    // IP header
    buf[0] = 0x45;
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[8] = 64;
    buf[9] = 6;
    buf[12..16].copy_from_slice(&src_ip.octets());
    buf[16..20].copy_from_slice(&dst_ip.octets());

    // TCP header
    let tcp_start = 20;
    buf[tcp_start..tcp_start + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[tcp_start + 2..tcp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[tcp_start + 4..tcp_start + 8].copy_from_slice(&seq.to_be_bytes());
    buf[tcp_start + 8..tcp_start + 12].copy_from_slice(&ack.to_be_bytes());
    buf[tcp_start + 12] = (5 << 4) as u8;
    buf[tcp_start + 13] = flags;
    buf[tcp_start + 14..tcp_start + 16].copy_from_slice(&TCP_WINDOW.to_be_bytes());
    buf[tcp_start + 20..].copy_from_slice(payload);

    // TCP checksum
    let tcp_cksum = calc_tcp_checksum(&buf, src_ip, dst_ip);
    buf[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

    // IP checksum
    let ip_cksum = ip_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    buf
}

fn calc_tcp_checksum(ip_pkt: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> u16 {
    let tcp_start = 20usize;
    let tcp_len = ip_pkt.len() - tcp_start;
    let mut sum: u32 = 0;

    // Pseudo header: src(4) + dst(4) + zero(1) + protocol(1) + tcp_len(2)
    let src_octs = src.octets();
    let dst_octs = dst.octets();
    for i in 0..2 {
        let w = u16::from_be_bytes([src_octs[i * 2], src_octs[i * 2 + 1]]);
        sum = sum.wrapping_add(w as u32);
    }
    for i in 0..2 {
        let w = u16::from_be_bytes([dst_octs[i * 2], dst_octs[i * 2 + 1]]);
        sum = sum.wrapping_add(w as u32);
    }
    sum = sum.wrapping_add(6u32); // protocol (TCP)
    sum = sum.wrapping_add(tcp_len as u32);

    // TCP segment with checksum field (offset 16,17) zeroed
    for i in (0..tcp_len).step_by(2) {
        let idx = tcp_start + i;
        let byte1 = if idx < ip_pkt.len() { ip_pkt[idx] } else { 0 };
        let byte2 = if idx + 1 < ip_pkt.len() && i != 16 { ip_pkt[idx + 1] } else { 0 };
        let word = u16::from_be_bytes([byte1, byte2]);
        sum = sum.wrapping_add(word as u32);
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..data.len()).step_by(2) {
        let byte1 = data[i];
        let byte2 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        sum = sum.wrapping_add(u16::from_be_bytes([byte1, byte2]) as u32);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
