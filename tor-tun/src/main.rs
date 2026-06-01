mod packet;
mod socks5;
mod tor;
mod tun;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();

    println!("╔══════════════════════════════════════════╗");
    println!("║           tor-tun v0.1.0                ║");
    println!("║  TUN-to-Tor SOCKS5 proxy                ║");
    println!("╚══════════════════════════════════════════╝");
    println!();
    println!("  SOCKS5 proxy: 127.0.0.1:9050");
    println!("  TUN device:   10.0.0.1/24");
    println!();
    println!("  ⚠ UDP is NOT routed through Tor yet");
    println!("  ⚠ Run with administrator/root privileges");
    println!("  ⚠ Windows: place wintun.dll next to the binary");
    println!();

    let tor_handle = tor::bootstrap().await?;

    tokio::spawn(async {
        if let Err(e) = tun::run_tun_reader().await {
            log::error!("TUN reader failed: {}", e);
        }
    });

    tokio::spawn(async {
        if let Err(e) = socks5::run_socks5_server(tor_handle).await {
            log::error!("SOCKS5 server failed: {}", e);
        }
    });

    tokio::signal::ctrl_c().await?;
    log::info!("Shutting down...");
    Ok(())
}
