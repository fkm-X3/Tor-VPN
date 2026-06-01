#![allow(dead_code)]

use std::net::Ipv4Addr;

pub const PROTOCOL_TCP: u8 = 6;
pub const PROTOCOL_UDP: u8 = 17;

#[derive(Debug)]
pub struct IpHeader {
    pub version: u8,
    pub ihl: u8,
    pub total_length: u16,
    pub protocol: u8,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
}

impl IpHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        let version_ihl = data[0];
        let version = version_ihl >> 4;
        let ihl = (version_ihl & 0x0f) as usize * 4;
        if version != 4 || data.len() < ihl {
            return None;
        }
        Some(Self {
            version,
            ihl: ihl as u8,
            total_length: u16::from_be_bytes([data[2], data[3]]),
            protocol: data[9],
            source: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            destination: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        })
    }
}

#[derive(Debug)]
pub struct TcpHeader {
    pub source_port: u16,
    pub dest_port: u16,
    pub flags: u8,
    pub data_offset: u8,
}

impl TcpHeader {
    pub fn parse(data: &[u8], ip_header_len: usize) -> Option<Self> {
        let tcp_start = ip_header_len;
        if data.len() < tcp_start + 20 {
            return None;
        }
        let data_offset_byte = data[tcp_start + 12];
        let data_offset = ((data_offset_byte >> 4) & 0x0f) * 4;
        if data.len() < tcp_start + data_offset as usize {
            return None;
        }
        Some(Self {
            source_port: u16::from_be_bytes([data[tcp_start], data[tcp_start + 1]]),
            dest_port: u16::from_be_bytes([data[tcp_start + 2], data[tcp_start + 3]]),
            flags: data[tcp_start + 13],
            data_offset,
        })
    }
}

#[derive(Debug)]
pub struct UdpHeader {
    pub source_port: u16,
    pub dest_port: u16,
    pub length: u16,
}

impl UdpHeader {
    pub fn parse(data: &[u8], ip_header_len: usize) -> Option<Self> {
        let udp_start = ip_header_len;
        if data.len() < udp_start + 8 {
            return None;
        }
        Some(Self {
            source_port: u16::from_be_bytes([data[udp_start], data[udp_start + 1]]),
            dest_port: u16::from_be_bytes([data[udp_start + 2], data[udp_start + 3]]),
            length: u16::from_be_bytes([data[udp_start + 4], data[udp_start + 5]]),
        })
    }
}
