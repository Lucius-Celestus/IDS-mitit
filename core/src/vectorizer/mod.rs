use crate::aegis::PacketVector;
use etherparse::PacketHeaders;

pub struct Vectorizer;

impl Vectorizer {
    /// Преобразует сырые данные пакета в вектор признаков для ИИ
    /// 
    /// # Arguments
    /// * `data` - Сырые байты пакета (включая заголовки Ethernet/IP/TCP/UDP)
    /// * `iat` - Inter-Arrival Time (время между пакетами) в секундах
    /// 
    /// # Returns
    /// `Some(PacketVector)` если парсинг успешен, `None` если пакет некорректен
    pub fn vectorize(data: &[u8], iat: f64) -> Option<PacketVector> {
        let headers = PacketHeaders::from_ethernet_slice(data).ok()?;

        // Извлекаем IP адрес источника (поддерживает IPv4 и IPv6)
        let src_ip = Self::extract_src_ip(&headers)?;

        // Извлекаем порт назначения (TCP/UDP) или 0 для других протоколов
        let dest_port = Self::extract_dest_port(&headers);

        // Извлекаем TCP флаги (если это TCP пакет)
        let tcp_flags = Self::extract_tcp_flags(&headers);

        // Получаем полезную нагрузку и вычисляем её энтропию
        let payload = headers.payload;
        let entropy = calculate_entropy(payload);
        
        // Берём первые 16 байт для анализа паттерна
        let head_len = std::cmp::min(payload.len(), 16);
        let payload_head = if head_len > 0 {
            payload[..head_len].to_vec()
        } else {
            Vec::new()
        };

        Some(PacketVector {
            packet_len: data.len() as u32,
            iat,
            entropy,
            payload_head,
            tcp_flags,
            src_ip,
            dest_port,
        })
    }

    /// Безопасное извлечение IP адреса источника (IPv4 или IPv6)
    fn extract_src_ip(headers: &PacketHeaders) -> Option<String> {
        headers.ip.as_ref().map(|ip_header| {
            match ip_header {
                etherparse::IpHeader::Version4(ipv4, _) => {
                    std::net::Ipv4Addr::from(ipv4.source).to_string()
                }
                etherparse::IpHeader::Version6(ipv6, _) => {
                    std::net::Ipv6Addr::from(ipv6.source).to_string()
                }
            }
        })
    }

    /// Извлечение порта назначения (поддерживает TCP и UDP)
    fn extract_dest_port(headers: &PacketHeaders) -> u32 {
        match &headers.transport {
            Some(etherparse::TransportHeader::Tcp(tcp)) => tcp.destination_port as u32,
            Some(etherparse::TransportHeader::Udp(udp)) => udp.destination_port as u32,
            _ => 0, // Для ICMP, IGMP и прочих протоколов без портов
        }
    }

    /// Извлечение TCP флагов (FIN, SYN, RST, PSH, ACK, URG)
    fn extract_tcp_flags(headers: &PacketHeaders) -> u32 {
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = &headers.transport {
            let mut flags: u32 = 0;
            if tcp.fin { flags |= 1 << 0; }  // FIN
            if tcp.syn { flags |= 1 << 1; }  // SYN
            if tcp.rst { flags |= 1 << 2; }  // RST
            if tcp.psh { flags |= 1 << 3; }  // PSH
            if tcp.ack { flags |= 1 << 4; }  // ACK
            if tcp.urg { flags |= 1 << 5; }  // URG
            flags
        } else {
            0
        }
    }
}

/// Вычисляет энтропию Шеннона для полезной нагрузки пакета
/// 
/// Энтропия показывает случайность данных:
/// - 0.0 = полностью предсказуемые данные
/// - 8.0 = максимальная случайность (сжато или зашифровано)
fn calculate_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f32;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .fold(0.0, |acc, &count| {
            let probability = count as f32 / len;
            acc - probability * probability.log2()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        assert_eq!(calculate_entropy(&[]), 0.0);
    }

    #[test]
    fn test_entropy_uniform() {
        // Все байты одинаковые = нулевая энтропия
        let data = vec![0xFF; 100];
        let entropy = calculate_entropy(&data);
        assert!(entropy < 0.01, "Expected near-zero entropy, got {}", entropy);
    }

    #[test]
    fn test_entropy_random() {
        // Максимальная энтропия для случайного распределения
        let data = (0..=255u8).collect::<Vec<_>>();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 7.0, "Expected high entropy, got {}", entropy);
    }
}