use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
use egui::{Color32, Frame, Margin, Rounding, Stroke, Vec2};

use crate::config::Config;
use crate::{packet, tcp, tor, tun, udp};

struct VpnStats {
    running: AtomicBool,
    tcp_sessions: AtomicUsize,
    udp_entries: AtomicUsize,
    error: Mutex<Option<String>>,
    log: Mutex<Vec<String>>,
}

impl VpnStats {
    fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            tcp_sessions: AtomicUsize::new(0),
            udp_entries: AtomicUsize::new(0),
            error: Mutex::new(None),
            log: Mutex::new(Vec::new()),
        }
    }
}

pub fn run(config: Config) -> anyhow::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 680.0])
            .with_min_inner_size([640.0, 480.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Tor-VPN",
        options,
        Box::new(|_cc| Box::new(TorVpnApp::new(config))),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}

struct TorVpnApp {
    config: Config,
    stats: Arc<VpnStats>,
    stop_signal: Arc<AtomicBool>,
    vpn_thread: Option<std::thread::JoinHandle<()>>,
    started_at: Option<Instant>,
    tcp_sessions: usize,
    udp_entries: usize,
    error: Option<String>,
    log: Vec<String>,
}

impl TorVpnApp {
    fn new(config: Config) -> Self {
        Self {
            config,
            stats: Arc::new(VpnStats::new()),
            stop_signal: Arc::new(AtomicBool::new(false)),
            vpn_thread: None,
            started_at: None,
            tcp_sessions: 0,
            udp_entries: 0,
            error: None,
            log: Vec::new(),
        }
    }

    fn start_vpn(&mut self) {
        let config = self.config.clone();
        let stats = self.stats.clone();
        let stop = self.stop_signal.clone();
        stop.store(false, Ordering::Relaxed);
        stats.running.store(true, Ordering::Relaxed);
        *stats.error.lock().unwrap() = None;
        stats.log.lock().unwrap().clear();
        self.started_at = Some(Instant::now());

        self.vpn_thread = Some(std::thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(r) => r,
                Err(e) => {
                    *stats.error.lock().unwrap() = Some(format!("Failed to create runtime: {e}"));
                    stats.running.store(false, Ordering::Relaxed);
                    return;
                }
            };
            rt.block_on(async move {
                run_vpn_engine(config, stats, stop).await;
            });
        }));
    }

    fn stop_vpn(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);
        if let Some(handle) = self.vpn_thread.take() {
            let _ = handle.join();
        }
        self.started_at = None;
    }

    fn format_uptime(&self) -> String {
        if let Some(start) = self.started_at {
            let d = start.elapsed();
            let h = d.as_secs() / 3600;
            let m = (d.as_secs() / 60) % 60;
            let s = d.as_secs() % 60;
            format!("{h:02}:{m:02}:{s:02}")
        } else {
            "--:--:--".to_string()
        }
    }
}

impl Drop for TorVpnApp {
    fn drop(&mut self) {
        self.stop_vpn();
    }
}

impl eframe::App for TorVpnApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let running = self.stats.running.load(Ordering::Relaxed);

        // Sync stats from background thread
        self.tcp_sessions = self.stats.tcp_sessions.load(Ordering::Relaxed);
        self.udp_entries = self.stats.udp_entries.load(Ordering::Relaxed);
        {
            let mut err_guard = self.stats.error.lock().unwrap();
            if let Some(msg) = err_guard.take() {
                self.error = Some(msg);
            }
        }
        {
            let mut log_guard = self.stats.log.lock().unwrap();
            if !log_guard.is_empty() {
                self.log.append(&mut log_guard);
                if self.log.len() > 1000 {
                    self.log.drain(0..self.log.len() - 1000);
                }
            }
        }

        // Detect unexpected thread exit
        if !running && self.vpn_thread.is_some() {
            if let Some(handle) = self.vpn_thread.take() {
                let _ = handle.join();
            }
            self.started_at = None;
        }

        if running {
            ctx.request_repaint_after(Duration::from_millis(500));
        }

        // ── Top bar ──
        egui::TopBottomPanel::top("top_bar")
            .frame(Frame {
                fill: if running {
                    Color32::from_rgb(18, 40, 18)
                } else {
                    Color32::from_rgb(30, 18, 18)
                },
                inner_margin: Margin::symmetric(12.0, 8.0),
                ..Default::default()
            })
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let (dot_color, status_text) = if running {
                        (Color32::GREEN, "● Running")
                    } else {
                        (Color32::RED, "● Stopped")
                    };
                    ui.heading(egui::RichText::new(status_text).color(dot_color).size(16.0));

                    // Uptime
                    if running {
                        ui.label(
                            egui::RichText::new(self.format_uptime())
                                .color(Color32::LIGHT_GRAY)
                                .size(14.0),
                        );
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if running {
                            let btn = egui::Button::new(
                                egui::RichText::new("⏹  Stop VPN").size(14.0),
                            )
                            .fill(Color32::from_rgb(140, 30, 30))
                            .min_size(Vec2::new(120.0, 32.0));
                            if ui.add(btn).clicked() {
                                self.stop_vpn();
                            }
                        } else {
                            let btn = egui::Button::new(
                                egui::RichText::new("▶  Start VPN").size(14.0),
                            )
                            .fill(Color32::from_rgb(30, 100, 30))
                            .min_size(Vec2::new(120.0, 32.0));
                            if ui.add(btn).clicked() {
                                self.error = None;
                                self.start_vpn();
                            }
                        }
                    });
                });
            });

        // ── Configuration (left) ──
        egui::SidePanel::left("config_panel")
            .resizable(true)
            .default_width(300.0)
            .frame(Frame {
                inner_margin: Margin::symmetric(12.0, 8.0),
                ..Default::default()
            })
            .show(ctx, |ui| {
                ui.heading("Configuration");
                ui.separator();

                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add_enabled_ui(!running, |ui| {
                        let style = ui.style_mut();
                        style.spacing.text_edit_width = 160.0;

                        ui.horizontal(|ui| {
                            ui.label("Tor Host:");
                            ui.text_edit_singleline(&mut self.config.tor_host);
                        });
                        ui.horizontal(|ui| {
                            ui.label("Tor Port:");
                            ui.add(
                                egui::DragValue::new(&mut self.config.tor_port).clamp_range(1..=65535),
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label("TUN IP:");
                            let mut s = self.config.tun_ip.to_string();
                            if ui.text_edit_singleline(&mut s).lost_focus() {
                                if let Ok(ip) = s.parse() {
                                    self.config.tun_ip = ip;
                                }
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.label("TUN Prefix:");
                            ui.add(
egui::DragValue::new(&mut self.config.tun_prefix_len)
                            .clamp_range(1..=30),
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label("Tor Outbound IP:");
                            let mut s = self.config.tor_outbound_ip.to_string();
                            if ui.text_edit_singleline(&mut s).lost_focus() {
                                if let Ok(ip) = s.parse() {
                                    self.config.tor_outbound_ip = ip;
                                }
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.label("MTU:");
                            ui.add(egui::DragValue::new(&mut self.config.mtu).clamp_range(576..=9000));
                        });
                        ui.horizontal(|ui| {
                            ui.label("TUN Name:");
                            ui.text_edit_singleline(&mut self.config.tun_name);
                        });
                        ui.horizontal(|ui| {
                            ui.label("Tor Dir:");
                            ui.text_edit_singleline(&mut self.config.tor_dir);
                        });
                        ui.horizontal(|ui| {
                            ui.label("Control Port:");
                            ui.add(
egui::DragValue::new(&mut self.config.tor_control_port)
                            .clamp_range(1..=65535),
                            );
                        });
                        ui.checkbox(
                            &mut self.config.skip_tor_download,
                            "Skip Tor Download",
                        );
                    });
                });
            });

        // ── Central area: Status + Log ──
        egui::CentralPanel::default()
            .frame(Frame {
                inner_margin: Margin::symmetric(12.0, 8.0),
                ..Default::default()
            })
            .show(ctx, |ui| {
                // Status cards
                ui.heading("Live Stats");
                ui.separator();
                ui.add_space(4.0);

                let card_frame = Frame {
                    fill: Color32::from_rgb(22, 22, 28),
                    rounding: Rounding::same(6.0),
                    stroke: Stroke::new(1.0, Color32::from_rgb(40, 40, 50)),
                    inner_margin: Margin::symmetric(12.0, 8.0),
                    ..Default::default()
                };

                ui.horizontal(|ui| {
                    card_frame.show(ui, |ui| {
                        ui.set_min_size(Vec2::new(120.0, 60.0));
                        ui.label(
                            egui::RichText::new("TCP Sessions")
                                .size(10.0)
                                .color(Color32::GRAY),
                        );
                        ui.label(
                            egui::RichText::new(format!("{}", self.tcp_sessions))
                                .size(28.0)
                                .color(Color32::from_rgb(100, 180, 255)),
                        );
                    });
                    ui.add_space(8.0);
                    card_frame.show(ui, |ui| {
                        ui.set_min_size(Vec2::new(120.0, 60.0));
                        ui.label(
                            egui::RichText::new("UDP NAT Entries")
                                .size(10.0)
                                .color(Color32::GRAY),
                        );
                        ui.label(
                            egui::RichText::new(format!("{}", self.udp_entries))
                                .size(28.0)
                                .color(Color32::from_rgb(255, 180, 100)),
                        );
                    });
                    ui.add_space(8.0);
                    card_frame.show(ui, |ui| {
                        ui.set_min_size(Vec2::new(120.0, 60.0));
                        ui.label(
                            egui::RichText::new("Uptime").size(10.0).color(Color32::GRAY),
                        );
                        ui.label(
                            egui::RichText::new(self.format_uptime())
                                .size(28.0)
                                .color(Color32::from_rgb(100, 255, 150)),
                        );
                    });
                });

                // Error display
                if let Some(err) = &self.error {
                    ui.add_space(8.0);
                    ui.colored_label(
                        Color32::RED,
                        egui::RichText::new(format!("⚠ {err}")).size(13.0),
                    );
                }

                // Log
                ui.add_space(12.0);
                ui.heading("Log");
                ui.separator();

                Frame {
                    fill: Color32::from_rgb(12, 12, 16),
                    rounding: Rounding::same(4.0),
                    inner_margin: Margin::symmetric(8.0, 4.0),
                    ..Default::default()
                }
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .max_height(280.0)
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for line in &self.log {
                                ui.label(
                                    egui::RichText::new(line)
                                        .size(11.0)
                                        .color(Color32::from_rgb(180, 200, 180)),
                                );
                            }
                            if self.log.is_empty() {
                                ui.label(
                                    egui::RichText::new("No log messages yet.")
                                        .size(11.0)
                                        .color(Color32::DARK_GRAY),
                                );
                            }
                        });
                });
            });
    }
}

async fn run_vpn_engine(config: Config, stats: Arc<VpnStats>, stop: Arc<AtomicBool>) {
    let log_msg = |msg: String| {
        stats.log.lock().unwrap().push(msg);
    };

    // Start Tor
    log_msg("Starting Tor...".to_string());
    let mut tor_manager = tor::TorManager::new(&config.tor_dir);
    if let Err(e) = tor_manager.start(&config).await {
        let err = format!("Tor failed to start: {e}");
        log_msg(err.clone());
        *stats.error.lock().unwrap() = Some(err);
        stats.running.store(false, Ordering::Relaxed);
        return;
    }
    log_msg("Tor is ready.".to_string());

    // Create TUN
    log_msg("Creating TUN interface...".to_string());
    let tun = match tun::TunHandle::new(&config) {
        Ok(t) => t,
        Err(e) => {
            let err = format!("TUN failed: {e}");
            log_msg(err.clone());
            *stats.error.lock().unwrap() = Some(err);
            let _ = tor_manager.stop();
            stats.running.store(false, Ordering::Relaxed);
            return;
        }
    };
    log_msg("TUN interface ready.".to_string());

    // Get physical interface index
    let physical_if_idx = match crate::get_physical_interface_index(&config.tun_name) {
        Ok(idx) => idx,
        Err(e) => {
            let err = format!("Failed to find network interface: {e}");
            log_msg(err.clone());
            *stats.error.lock().unwrap() = Some(err);
            let _ = tor_manager.stop();
            stats.running.store(false, Ordering::Relaxed);
            return;
        }
    };

    let mut tcp_proxy = tcp::TcpProxy::new(
        physical_if_idx,
        config.tor_host.clone(),
        config.tor_port,
        config.tor_outbound_ip,
        config.tun_ip,
    );

    let udp_shutdown = Arc::new(AtomicBool::new(false));
    let mut udp_forwarder = udp::UdpForwarder::new(physical_if_idx, udp_shutdown);

    let tun_writer = |data: &[u8]| {
        if let Err(e) = tun.write(data) {
            tracing::warn!("TUN write error: {e}");
        }
    };

    log_msg("VPN is running.".to_string());
    let mut tick: u64 = 0;

    loop {
        if stop.load(Ordering::Relaxed) {
            log_msg("Shutting down...".to_string());
            break;
        }

        while let Some(packet) = tun.try_read() {
            if let Some(info) = packet::classify_packet(&packet) {
                match info.transport {
                    packet::TransportInfo::Udp(_) => {
                        udp_forwarder
                            .handle_packet(&packet, config.tun_ip, config.tor_outbound_ip);
                    }
                    _ => {
                        tcp_proxy.handle_packet(&packet);
                    }
                }
            }
        }

        tcp_proxy.process_responses(&tun_writer);
        udp_forwarder.poll_responses(&tun_writer);

        tick += 1;
        if tick % 40 == 0 {
            stats
                .tcp_sessions
                .store(tcp_proxy.session_count(), Ordering::Relaxed);
            stats
                .udp_entries
                .store(udp_forwarder.entry_count(), Ordering::Relaxed);
        }

        std::thread::sleep(Duration::from_millis(5));
    }

    let _ = tor_manager.stop();
    stats.running.store(false, Ordering::Relaxed);
    log_msg("VPN stopped.".to_string());
}
