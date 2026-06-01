use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

const TOR_VERSION: &str = "15.0.14";

pub struct TorManager {
    process: Option<Child>,
    tor_dir: PathBuf,
    shutdown: Arc<AtomicBool>,
}

impl TorManager {
    pub fn new(tor_dir: &str) -> Self {
        Self {
            process: None,
            tor_dir: PathBuf::from(tor_dir),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn start(&mut self, config: &crate::config::Config) -> Result<()> {
        let tor_exe = self.tor_dir.join("Tor").join("tor.exe");

        if !tor_exe.exists() {
            if config.skip_tor_download {
                anyhow::bail!("Tor binary not found at {:?} and --skip-tor-download is set", tor_exe);
            }
            info!("Tor binary not found. Downloading...");
            self.download_tor().await?;
        } else {
            info!("Tor binary found at {:?}", tor_exe);
        }

        let data_dir = self.tor_dir.join("Data");
        std::fs::create_dir_all(&data_dir).context("Failed to create Tor data directory")?;

        let mut cmd = Command::new(&tor_exe);
        cmd.args([
            "--SocksPort", &config.tor_port.to_string(),
            "--ControlPort", &config.tor_control_port.to_string(),
            "--DataDirectory", data_dir.to_str().unwrap(),
            "--OutboundBindAddress", &config.tor_outbound_ip.to_string(),
            "--Log", "notice stderr",
            "__OwningControllerProcess", &std::process::id().to_string(),
        ]);
        cmd.stdout(Stdio::null())
            .stderr(Stdio::null());

        info!("Starting Tor...");
        let child = cmd.spawn().context("Failed to spawn Tor process")?;
        self.process = Some(child);

        let shutdown = self.shutdown.clone();
        std::thread::spawn(move || {
            while !shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(5));
            }
        });

        self.wait_for_ready(config).await?;
        info!("Tor is ready on {}:{}", config.tor_host, config.tor_port);
        Ok(())
    }

    async fn wait_for_ready(&self, config: &crate::config::Config) -> Result<()> {
        let addr = format!("{}:{}", config.tor_host, config.tor_port);
        for i in 0..60 {
            if self.shutdown.load(Ordering::Relaxed) {
                anyhow::bail!("Tor shutdown requested during startup");
            }
            match std::net::TcpStream::connect(&addr) {
                Ok(mut stream) => {
                    let handshake = [5u8, 1, 0];
                    if stream.write_all(&handshake).is_ok() {
                        let mut resp = [0u8; 2];
                        if stream.read_exact(&mut resp).is_ok() && resp == [5, 0] {
                            return Ok(());
                        }
                    }
                }
                Err(_) => {}
            }
            if i % 5 == 0 {
                info!("Waiting for Tor to start... ({}s)", i + 1);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        anyhow::bail!("Tor did not become ready within 60 seconds");
    }

    async fn download_tor(&self) -> Result<()> {
        let arch = if cfg!(target_pointer_width = "64") {
            "x86_64"
        } else {
            "i686"
        };
        let filename = format!("tor-expert-bundle-windows-{arch}-{TOR_VERSION}.tar.gz");
        let url = format!("https://dist.torproject.org/torbrowser/{TOR_VERSION}/{filename}");

        info!("Downloading Tor from {url}...");
        let response = reqwest::get(&url)
            .await
            .context("Failed to download Tor expert bundle")?;
        let bytes = response.bytes().await?;

        info!("Downloaded {} bytes. Extracting...", bytes.len());
        std::fs::create_dir_all(&self.tor_dir)?;

        let decoder = flate2::read::GzDecoder::new(&bytes[..]);
        let mut archive = tar::Archive::new(decoder);
        archive.unpack(&self.tor_dir).context("Failed to extract Tor bundle")?;

        // Handle nested directory
        let nested = self.tor_dir.join(format!("tor-expert-bundle-windows-{arch}-{TOR_VERSION}"));
        if nested.exists() {
            for entry in std::fs::read_dir(&nested)? {
                let entry = entry?;
                let path = entry.path();
                let dest = self.tor_dir.join(entry.file_name());
                if path.is_dir() {
                    std::fs::create_dir_all(&dest)?;
                    copy_dir_recursive(&path, &dest)?;
                } else {
                    let _ = std::fs::copy(&path, &dest);
                }
            }
        }

        info!("Tor extracted to {:?}", self.tor_dir);
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(mut child) = self.process.take() {
            info!("Stopping Tor process (PID {})", child.id());
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(())
    }
}

impl Drop for TorManager {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let dest = dst.join(entry.file_name());
        if path.is_dir() {
            std::fs::create_dir_all(&dest)?;
            copy_dir_recursive(&path, &dest)?;
        } else {
            std::fs::copy(&path, &dest)?;
        }
    }
    Ok(())
}
