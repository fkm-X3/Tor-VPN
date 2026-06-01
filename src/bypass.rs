use std::net::Ipv4Addr;

/// Check if a packet should bypass the proxy and be handled directly.
/// Returns true if the packet should NOT be processed by the VPN.
pub fn should_bypass(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    tor_outbound_ip: Ipv4Addr,
    tor_socks_port: u16,
    tun_ip: Ipv4Addr,
) -> bool {
    // 1. Tor's own outbound traffic: detected by source IP
    //    Tor binds to this IP via OutboundBindAddress
    if src_ip == tor_outbound_ip {
        return true;
    }

    // 2. Traffic to/from Tor's SOCKS port on localhost
    let is_loopback = dst_ip.is_loopback() || src_ip.is_loopback();
    if is_loopback && (src_port == tor_socks_port || dst_port == tor_socks_port) {
        return true;
    }

    // 3. Generic loopback traffic (127.0.0.0/8) — never route through TUN
    if dst_ip.is_loopback() || src_ip.is_loopback() {
        return true;
    }

    // 4. Traffic to/from the TUN interface itself
    if src_ip == tun_ip || dst_ip == tun_ip {
        return true;
    }

    // 5. Link-local and multicast
    if dst_ip.is_link_local() || dst_ip.is_multicast() {
        return true;
    }

    false
}
