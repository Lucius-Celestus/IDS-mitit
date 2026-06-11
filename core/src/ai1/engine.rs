use crate::aegis::PacketVector;

/// Вердикт локального анализатора
pub struct Verdict {
    pub drop: bool,
    pub confidence: f32,
    pub attack_type: String,
}

/// AI-1: Edge Detection Engine (Локальный фильтр)
pub struct AI1 {
    threshold: f32,
}

impl AI1 {
    pub fn new(threshold: f32) -> Self {
        Self { threshold }
    }

    /// Полноценный анализ вектора признаков
    pub fn check(&self, vector: &PacketVector) -> Option<Verdict> {
        let mut score: f32 = 0.0;
        let mut detections = Vec::new();

        // 1. Детекция Flood-атак (на основе Inter-Arrival Time)
        // Если пакеты летят быстрее 100 мкс - это аномально для человека
        if vector.iat > 0.0 && vector.iat < 0.0001 {
            score += 0.5;
            detections.push("High Frequency Flood");
        }

        // 2. Детекция эксфильтрации/туннелирования (Энтропия + Размер)
        // Высокая энтропия в больших пакетах часто указывает на зашифрованный трафик/шелл-код
        if vector.entropy > 7.9 {
            if vector.packet_len > 1000 {
                score += 0.5;
                detections.push("Encrypted Exfiltration");
            } else {
                score += 0.25;
                detections.push("High Entropy Payload");
            }
        }

        // 3. Анализ TCP-флагов (Сканирование и аномалии)
        // SYN=1, ACK=0 при малом размере — типичный SYN-скан
        if (vector.tcp_flags & 0x02 != 0) && (vector.tcp_flags & 0x10 == 0) {
            if vector.packet_len < 64 {
                score += 0.35;
                detections.push("SYN Scan Pattern");
            }
        }

        // 4. Анализ аномальных комбинаций (например, NULL-scan или XMAS)
        if vector.tcp_flags == 0 {
            score += 0.6;
            detections.push("NULL Scan");
        } else if vector.tcp_flags == 0x29 { // FIN + PSH + URG
            score += 0.7;
            detections.push("XMAS Scan");
        }

        // Финальное решение
        if score >= self.threshold {
            return Some(Verdict {
                drop: score > 0.8, // Дропаем только если уверены на 80%+
                confidence: score.min(1.0),
                attack_type: detections.join(" | "),
            });
        }

        None
    }
}