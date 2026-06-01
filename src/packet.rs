use std::net::Ipv4Addr;

pub const IP_PROTOCOL_TCP: u8 = 6;
pub const IP_PROTOCOL_UDP: u8 = 17;

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset_reserved_flags: u16,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub ip_header: Ipv4Header,
    pub transport: TransportInfo,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum TransportInfo {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Other { protocol: u8 },
}

pub fn parse_ipv4(data: &[u8]) -> Option<(Ipv4Header, usize)> {
    if data.len() < 20 {
        return None;
    }
    let version_ihl = data[0];
    let ihl = (version_ihl & 0x0f) as usize;
    if ihl < 5 || data.len() < ihl * 4 {
        return None;
    }
    let header = Ipv4Header {
        version_ihl,
        dscp_ecn: data[1],
        total_length: u16::from_be_bytes([data[2], data[3]]),
        identification: u16::from_be_bytes([data[4], data[5]]),
        flags_fragment: u16::from_be_bytes([data[6], data[7]]),
        ttl: data[8],
        protocol: data[9],
        header_checksum: u16::from_be_bytes([data[10], data[11]]),
        src_ip: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
        dst_ip: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
    };
    Some((header, ihl * 4))
}

pub fn parse_tcp(data: &[u8]) -> Option<(TcpHeader, usize)> {
    if data.len() < 20 {
        return None;
    }
    let data_offset = ((data[12] >> 4) & 0x0f) as usize;
    if data_offset < 5 || data.len() < data_offset * 4 {
        return None;
    }
    let header = TcpHeader {
        src_port: u16::from_be_bytes([data[0], data[1]]),
        dst_port: u16::from_be_bytes([data[2], data[3]]),
        sequence_number: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        acknowledgment_number: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
        data_offset_reserved_flags: u16::from_be_bytes([data[12], data[13]]),
        window_size: u16::from_be_bytes([data[14], data[15]]),
        checksum: u16::from_be_bytes([data[16], data[17]]),
        urgent_pointer: u16::from_be_bytes([data[18], data[19]]),
    };
    Some((header, data_offset * 4))
}

pub fn parse_udp(data: &[u8]) -> Option<(UdpHeader, usize)> {
    if data.len() < 8 {
        return None;
    }
    let header = UdpHeader {
        src_port: u16::from_be_bytes([data[0], data[1]]),
        dst_port: u16::from_be_bytes([data[2], data[3]]),
        length: u16::from_be_bytes([data[4], data[5]]),
        checksum: u16::from_be_bytes([data[6], data[7]]),
    };
    Some((header, 8))
}

pub fn classify_packet(data: &[u8]) -> Option<PacketInfo> {
    let (ip_header, ip_header_len) = parse_ipv4(data)?;
    let total_len = ip_header.total_length as usize;
    let transport_start = ip_header_len;
    let transport_end = total_len.min(data.len());

    let transport_data = &data[transport_start..transport_end];

    let (transport, payload_start) = match ip_header.protocol {
        IP_PROTOCOL_TCP => {
            let (tcp, tcp_len) = parse_tcp(transport_data)?;
            (TransportInfo::Tcp(tcp), tcp_len)
        }
        IP_PROTOCOL_UDP => {
            let (udp, udp_len) = parse_udp(transport_data)?;
            (TransportInfo::Udp(udp), udp_len)
        }
        proto => (TransportInfo::Other { protocol: proto }, 0),
    };

    let payload = transport_data[payload_start..].to_vec();

    Some(PacketInfo {
        ip_header,
        transport,
        payload,
    })
}

pub fn syn_flag(flags: u16) -> bool {
    flags & 0x002 != 0
}

pub fn ack_flag(flags: u16) -> bool {
    flags & 0x010 != 0
}

pub fn rst_flag(flags: u16) -> bool {
    flags & 0x004 != 0
}

pub fn fin_flag(flags: u16) -> bool {
    flags & 0x001 != 0
}

pub fn psh_flag(flags: u16) -> bool {
    flags & 0x008 != 0
}

pub fn build_ipv4_packet(
    payload: &[u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    ttl: u8,
    identification: u16,
) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut buf = vec![0u8; total_len];

    buf[0] = 0x45; // IPv4, IHL=5
    buf[1] = 0;    // DSCP/ECN
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&identification.to_be_bytes());
    buf[6] = 0x40; // Don't fragment
    buf[7] = 0;
    buf[8] = ttl;
    buf[9] = protocol;
    // checksum at 10-11, set to 0 for now
    buf[12..16].copy_from_slice(&src_ip.octets());
    buf[16..20].copy_from_slice(&dst_ip.octets());
    buf[20..].copy_from_slice(payload);

    // Compute checksum
    let checksum = ip_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&checksum.to_be_bytes());

    buf
}

fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], if chunk.len() > 1 { chunk[1] } else { 0 }]);
        sum = sum.wrapping_add(word as u32);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
