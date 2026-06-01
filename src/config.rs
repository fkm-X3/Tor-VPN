use clap::Parser;
use std::net::Ipv4Addr;

#[derive(Parser, Clone)]
#[command(name = "tor-vpn", version, about = "A VPN that routes TCP through Tor via a TUN interface")]
pub struct Config {
    #[arg(long, default_value = "127.0.0.1")]
    pub tor_host: String,

    #[arg(long, default_value = "9050")]
    pub tor_port: u16,

    #[arg(long, default_value = "10.0.0.1")]
    pub tun_ip: Ipv4Addr,

    #[arg(long, default_value = "24")]
    pub tun_prefix_len: u8,

    #[arg(long, default_value = "10.0.0.2")]
    pub tor_outbound_ip: Ipv4Addr,

    #[arg(long, default_value = "1500")]
    pub mtu: usize,

    #[arg(long, default_value = "TorVPN")]
    pub tun_name: String,

    #[arg(long, default_value = "tor")]
    pub tor_dir: String,

    #[arg(long, default_value = "9051")]
    pub tor_control_port: u16,

    #[arg(long)]
    pub skip_tor_download: bool,
}
