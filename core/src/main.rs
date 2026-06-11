pub mod aegis {
    tonic::include_proto!("aegis");
}

mod blocker;
mod capture;
mod vectorizer;

use aegis::aegis_service_client::AegisServiceClient;
use std::collections::HashMap;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{Duration, Instant};
use chrono::Utc;
use serde::Serialize;
use tokio::time::sleep;

// === Конфигурация ===
const CACHE_TTL_SECS: u64 = 600;
const MAX_CACHE_SIZE: usize = 10000;
const RECONNECT_DELAY_SECS: u64 = 5;
const LOG_PATH: &str = "/app/data/logs/alerts.jsonl";
const DEFAULT_IFACE: &str = "wlp3s0";
const DEFAULT_BRAIN_ADDR: &str = "http://127.0.0.1:50051";

// === Структура боевого лога ===
#[derive(Serialize, Debug)]
struct CoreAlert {
    timestamp: String,
    src_ip: String,
    dest_port: u32,
    confidence: f32,
    #[serde(rename = "type")]
    alert_type: String,
    source: String,
}

// === Состояние системы ===
struct AegisState {
    client: AegisServiceClient<tonic::transport::Channel>,
    trusted_ips: HashMap<String, Instant>,
    activity_radar: HashMap<String, (u32, Instant)>,
    cache_ttl: Duration,
    max_cache_size: usize,
    last_packet_time: Instant,
}

impl AegisState {
    fn new(client: AegisServiceClient<tonic::transport::Channel>) -> Self {
        Self {
            client,
            trusted_ips: HashMap::new(),
            activity_radar: HashMap::new(),
            cache_ttl: Duration::from_secs(CACHE_TTL_SECS),
            max_cache_size: MAX_CACHE_SIZE,
            last_packet_time: Instant::now(),
        }
    }

    fn is_trusted(&mut self, src_ip: &str) -> bool {
        if let Some(time_added) = self.trusted_ips.get(src_ip) {
            if time_added.elapsed() < self.cache_ttl {
                return true;
            } else {
                self.trusted_ips.remove(src_ip);
            }
        }
        false
    }

    fn add_trusted(&mut self, src_ip: String) {
        if self.trusted_ips.len() >= self.max_cache_size {
            self.cleanup_cache();
        }
        self.trusted_ips.insert(src_ip, Instant::now());
    }

    fn cleanup_cache(&mut self) {
        self.trusted_ips.retain(|_, time_added| time_added.elapsed() < self.cache_ttl);
        self.activity_radar.retain(|_, (_, time_started)| time_started.elapsed() < Duration::from_secs(2));
    }
}

async fn connect_to_brain(brain_addr: &str) -> Result<AegisServiceClient<tonic::transport::Channel>, Box<dyn Error>> {
    loop {
        match AegisServiceClient::connect(brain_addr.to_string()).await {
            Ok(client) => {
                println!("[+] Успешно подключено к Brain: {}", brain_addr);
                return Ok(client);
            }
            Err(e) => {
                eprintln!("[!] Ошибка подключения к Brain: {}. Повторная попытка через {} сек...", e, RECONNECT_DELAY_SECS);
                sleep(Duration::from_secs(RECONNECT_DELAY_SECS)).await;
            }
        }
    }
}

fn log_alert(alert: &CoreAlert) -> Result<(), Box<dyn Error>> {
    let json_string = serde_json::to_string(alert)?;
    let mut file = OpenOptions::new().create(true).append(true).open(LOG_PATH)?;
    writeln!(file, "{}", json_string)?;
    file.flush()?;
    Ok(())
}

async fn process_verdict(state: &mut AegisState, vector: &aegis::PacketVector, verdict: &aegis::Verdict) -> Result<(), Box<dyn Error>> {
    if verdict.drop {
        eprintln!(
            "[ALERT] ⚠️  УГРОЗА ПОДТВЕРЖДЕНА ИИ: IP {} на порт {} (Confidence: {:.2}%)",
            vector.src_ip, vector.dest_port, verdict.confidence * 100.0
        );

        // Runtime проверка BLOCK_MODE вместо compile-time флагов
        let block_mode = std::env::var("BLOCK_MODE").unwrap_or_else(|_| "shadow".to_string());
        if block_mode.to_lowercase() == "production" {
            blocker::block_ip(&vector.src_ip);
        } else {
            println!("[SHADOW] 🎭 Режим логирования (не блокируем): IP {} был бы заблокирован", vector.src_ip);
        }

        let alert = CoreAlert {
            timestamp: Utc::now().to_rfc3339(),
            src_ip: vector.src_ip.clone(),
            dest_port: vector.dest_port,
            confidence: verdict.confidence,
            alert_type: "HYBRID_AI_DETECTION".to_string(),
            source: "AEGIS_FUSION_CORE".to_string(),
        };
        let _ = log_alert(&alert);
    } else {
        println!("[OK] ✓ IP {} признан легитимным Brain", vector.src_ip);
        state.add_trusted(vector.src_ip.clone());
    }
    Ok(())
}

async fn packet_processing_loop(mut cap: capture::live::Live, state: &mut AegisState) -> Result<(), Box<dyn Error>> {
    println!("[*] Начинаем обработку пакетов...");

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let now = Instant::now();
                let iat = now.duration_since(state.last_packet_time).as_secs_f64();
                state.last_packet_time = now;

                if let Some(vector) = vectorizer::Vectorizer::vectorize(&packet.data, iat) {
                    
                    // === 1. РАДАР ЧАСТОТЫ (СБОР КОНТЕКСТА) ===
                    let mut current_rate = 1;
                    {
                        let radar_entry = state.activity_radar
                            .entry(vector.src_ip.clone())
                            .or_insert((0, Instant::now()));

                        radar_entry.0 += 1;
                        if radar_entry.1.elapsed() > Duration::from_secs(1) {
                            radar_entry.0 = 1;
                            radar_entry.1 = Instant::now();
                        }
                        current_rate = radar_entry.0;
                    }

                    // === 2. ДИНАМИЧЕСКИЙ ОТЗЫВ ДОВЕРИЯ ===
                    // Если IP из кэша начал слать более 10 пакетов/сек, он лишается белого билета
                    if current_rate > 10 {
                        state.trusted_ips.remove(&vector.src_ip);
                    }

                    // === 3. ПРОВЕРКА КЭША ===
                    if state.is_trusted(&vector.src_ip) {
                        continue;
                    }

                    // === 4. АНАЛИЗ И СЛИЯНИЕ ДАННЫХ (FUSION) ===
                    let request = tonic::Request::new(vector.clone());
                    match state.client.analyze(request).await {
                        Ok(response) => {
                            let mut verdict = response.into_inner();

                            // Математика нейросети + контекст
                            let ai_base = verdict.confidence;
                            let freq_weight = 0.015; // Вес частоты: +15% угрозы за каждые 10 пак/сек
                            let freq_penalty = (current_rate as f32) * freq_weight;
                            
                            // Финальная формула (не может быть больше 1.0)
                            let final_confidence = (ai_base + freq_penalty).min(1.0);

                            // Отражаем ход мысли в консоли (только если есть подозрения)
                            if current_rate > 5 || final_confidence > 0.4 {
                                println!(
                                    "[THOUGHT] 🧠 F(x) = AI_Base({:.2}) + [Freq({} pkt/s) * W({:.3})] = Final_Conf: {:.2}",
                                    ai_base, current_rate, freq_weight, final_confidence
                                );
                            }

                            // Перезаписываем вердикт Питона нашим гибридным решением
                            verdict.confidence = final_confidence;
                            verdict.drop = final_confidence >= 0.85;

                            if let Err(e) = process_verdict(state, &vector, &verdict).await {
                                eprintln!("[!] Ошибка обработки вердикта: {}", e);
                            }
                        }
                        Err(e) => {
                            eprintln!("[!] Ошибка запроса к Brain: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                let error_str = e.to_string();
                if !error_str.contains("timeout") { eprintln!("[!] Ошибка захвата: {}", e); }
            }
        }

        if state.last_packet_time.elapsed() > Duration::from_secs(2) {
            state.cleanup_cache();
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let iface = std::env::var("IFACE").unwrap_or_else(|_| DEFAULT_IFACE.to_string());
    let brain_addr = std::env::var("BRAIN_ADDR").unwrap_or_else(|_| DEFAULT_BRAIN_ADDR.to_string());

    println!("╔═══════════════════════════════════════╗");
    println!("║  🛡️  Aegis Hybrid Fusion Engine  🛡️  ║");
    println!("╚═══════════════════════════════════════╝");
    println!("[*] Интерфейс: {}", iface);
    println!("[*] Brain адрес: {}", brain_addr);

    let cap = match capture::live::Live::new(&iface) {
        Ok(c) => c,
        Err(e) => { eprintln!("[!] Ошибка захвата: {}", e); return Err(e); }
    };

    let client = connect_to_brain(&brain_addr).await?;
    let mut state = AegisState::new(client);

    println!("[+] Система Aegis готова!");
    
    // Проверяем BLOCK_MODE переменную
    let block_mode = std::env::var("BLOCK_MODE").unwrap_or_else(|_| "shadow".to_string());
    let mode_friendly = if block_mode.to_lowercase() == "production" { 
        "🔴 PRODUCTION (активная блокировка через iptables)" 
    } else { 
        "🟢 SHADOW MODE (только логирование, без блокировки)" 
    };
    println!("[+] Режим блокировки: {}", mode_friendly);
    println!("[+] BLOCK_MODE={}", block_mode);
    println!();

    packet_processing_loop(cap, &mut state).await?;
    Ok(())
}