use anyhow::{Context, Result};
use std::sync::Arc;
use uuid::Uuid;
use wintun::{Adapter, Session, Wintun};
use tracing::info;

use crate::config::Config;

pub struct TunHandle {
    _dll: Wintun,
    _adapter: Arc<Adapter>,
    session: Arc<Session>,
    pub _mtu: usize,
}

impl TunHandle {
    pub fn new(config: &Config) -> Result<Self> {
        let dll: Wintun =
            unsafe { wintun::load_from_path("wintun.dll") }
                .context("Failed to load wintun.dll. Run setup-tun.ps1 first.")?;

        let guid = Uuid::new_v4().as_u128();
        let adapter = Adapter::create(&dll, &config.tun_name, "Tor VPN", Some(guid))
            .or_else(|_| Adapter::open(&dll, &config.tun_name))
            .context("Failed to create/open TUN adapter")?;

        let mask = subnet_mask(config.tun_prefix_len);

        // Set IP on TUN adapter via netsh
        let set_addr = std::process::Command::new("netsh")
            .args([
                "interface", "ip", "set", "address",
                &config.tun_name, "static",
                &config.tun_ip.to_string(), &mask,
            ])
            .output();
        if let Ok(out) = set_addr {
            if !out.status.success() {
                let err = String::from_utf8_lossy(&out.stderr);
                tracing::warn!("netsh set address: {err}");
            }
        }

        // Add secondary IP for Tor's outbound bind
        let _ = std::process::Command::new("netsh")
            .args([
                "interface", "ip", "add", "address",
                &config.tun_name,
                &config.tor_outbound_ip.to_string(), &mask,
            ])
            .output();

        // Add split default routes through TUN
        if let Ok(if_idx) = get_tun_interface_index(&config.tun_name) {
            let r1 = subnet_mask(1);
            for dest in ["0.0.0.0", "128.0.0.0"] {
                let _ = std::process::Command::new("route")
                    .args(["add", dest, "mask", &r1, &config.tun_ip.to_string(), "if", &if_idx.to_string(), "metric", "1"])
                    .output();
            }
        }

        let session = Arc::new(adapter.start_session(0x400000)
            .context("Failed to start TUN session")?);

        info!("TUN adapter '{}' created with IP {}/{}", config.tun_name, config.tun_ip, config.tun_prefix_len);

        Ok(Self { _dll: dll, _adapter: adapter, session, _mtu: config.mtu })
    }

    pub fn try_read(&self) -> Option<Vec<u8>> {
        self.session.try_receive().ok().and_then(|opt| {
            opt.map(|pkt| {
                let data = pkt.bytes().to_vec();
                drop(pkt);
                data
            })
        })
    }

    pub fn write(&self, data: &[u8]) -> Result<()> {
        let size: u16 = data.len().try_into()
            .context("Packet too large for wintun")?;
        let mut pkt = self.session
            .allocate_send_packet(size)
            .context("Failed to allocate TUN send packet")?;
        pkt.bytes_mut().copy_from_slice(data);
        self.session.send_packet(pkt);
        Ok(())
    }
}

fn subnet_mask(prefix_len: u8) -> String {
    let mask = if prefix_len >= 32 { !0u32 } else { !0u32 << (32 - prefix_len) };
    let o = mask.to_be_bytes();
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

fn get_tun_interface_index(name: &str) -> Result<u32> {
    let output = std::process::Command::new("netsh")
        .args(["interface", "ip", "show", "interface"])
        .output()
        .context("Failed to list interfaces")?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if line.trim().ends_with(name) {
            if let Some(idx) = line.split_whitespace().next() {
                if let Ok(n) = idx.parse::<u32>() {
                    return Ok(n);
                }
            }
        }
    }
    anyhow::bail!("Could not find interface index for {name}")
}
