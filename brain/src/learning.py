"""
Адаптивная система обучения AEGIS - Интеллектуальная эвристика на основе ИИ
"""

import numpy as np
from typing import Dict, Tuple, Optional
from datetime import datetime


class IntelligentHeuristics:
    """Система эвристик, которая полагается на ИИ и логирует оценку как формулу"""
    
    def __init__(self, model):
        self.model = model
        self.confidence_history = []
        self.feature_importance = {
            'entropy': 0.4,      # Энтропия важна для шифрованных/сжатых данных
            'iat': 0.3,          # IAT важна для temporality patterns
            'packet_len': 0.2,   # Размер пакета
            'tcp_flags': 0.1     # TCP флаги
        }
        
    def normalize_features(self, features: Dict[str, float]) -> Dict[str, float]:
        """Нормализация признаков в диапазон [0, 1] для анализа"""
        normalized = {}
        
        # packet_len: от 0 до 65535 байт
        packet_len = features.get('packet_len', 0)
        normalized['packet_len'] = min(packet_len / 65535.0, 1.0)
        
        # iat: от 0 до 1 сек (логарифмическая шкала)
        iat = features.get('iat', 0.001)
        if iat > 0:
            normalized['iat'] = min(-np.log10(iat) / 6.0, 1.0)  # Логарифмическая нормировка
        else:
            normalized['iat'] = 1.0
        
        # entropy: от 0 до 8 (максимум Shannon entropy)
        entropy = features.get('entropy', 0)
        normalized['entropy'] = min(entropy / 8.0, 1.0)
        
        # tcp_flags: от 0 до 63 (6 флагов)
        tcp_flags = features.get('tcp_flags', 0)
        normalized['tcp_flags'] = min(tcp_flags / 63.0, 1.0)
        
        return normalized
    
    def extract_anomaly_signals(self, features: Dict[str, float], normalized: Dict[str, float]) -> Dict[str, float]:
        """Извлечение сигналов аномалии из признаков"""
        signals = {}
        
        # Сигнал 1: Высокая энтропия при малом размере пакета = сжато/шифровано
        signals['entropy_anomaly'] = (
            normalized['entropy'] * (1 - normalized['packet_len'])
        )
        
        # Сигнал 2: Очень быстрые пакеты (микросекундные интервалы) = машинная атака
        iat = features.get('iat', 0.001)
        signals['rapid_fire'] = (
            1.0 if iat < 0.00001 else  # < 10 микросекунд
            0.7 if iat < 0.0001 else    # < 100 микросекунд
            0.3 if iat < 0.001 else     # < 1 миллисекунда
            0.1
        )
        
        # Сигнал 3: SYN флаг (бит 1) без других флагов = сканирование портов
        tcp_flags = features.get('tcp_flags', 0)
        syn_flag = bool(tcp_flags & 0x02)
        ack_flag = bool(tcp_flags & 0x10)
        signals['syn_only'] = (
            0.8 if (syn_flag and not ack_flag) else 0.0
        )
        
        # Сигнал 4: Flow entropy крайностей (очень высокая или низкая)
        entropy = features.get('entropy', 4.0)
        signals['entropy_extremity'] = (
            0.9 if entropy > 7.5 else
            0.7 if entropy > 6.5 else
            0.2 if entropy < 2.0 else
            0.0
        )
        
        return signals
    
    def analyze_with_ai(self, features: Dict[str, float]) -> Tuple[float, str]:
        """
        Анализ пакета с ИИ-моделью и возвращение уверенности + формула расчета
        
        Returns:
            confidence: Вероятность атаки [0.0, 1.0]
            formula: Формула расчета для логирования
        """
        if not self.model:
            return self._fallback_heuristics(features)
        
        # Нормализуем признаки
        normalized = self.normalize_features(features)
        
        # Извлекаем сигналы аномалии
        signals = self.extract_anomaly_signals(features, normalized)
        
        # Получаем предсказание от ИИ
        ai_confidence = self._get_ai_prediction(features)
        
        # Комбинированная оценка: ИИ + сигналы + паттерны
        combined_confidence = self._combine_scores(ai_confidence, signals, normalized)
        
        # Генерируем человеко-читаемую формулу
        formula = self._build_formula(features, signals, ai_confidence, combined_confidence)
        
        return combined_confidence, formula
    
    def _get_ai_prediction(self, features: Dict[str, float]) -> float:
        """Получить предсказание от ИИ модели"""
        try:
            if hasattr(self.model, 'predict_proba'):
                # scikit-learn - 4 features: packet_len, iat, entropy, tcp_flags
                X = [[features.get('packet_len', 0), 
                      features.get('iat', 0.001), 
                      features.get('entropy', 4.0),
                      features.get('tcp_flags', 0)]]
                probs = self.model.predict_proba(X)[0]
                return float(probs[1])  # Вероятность класса "атака"
                
            elif hasattr(self.model, 'predict_proba_one'):
                # River
                probs = self.model.predict_proba_one(features)
                return float(probs.get(1, 0.5))
                
            elif hasattr(self.model, 'predict_one'):
                # River без вероятностей
                pred = self.model.predict_one(features)
                return 0.8 if pred == 1 else 0.2
                
        except Exception as e:
            print(f"[!] Ошибка ИИ: {e}", flush=True)
            return 0.5
        
        return 0.5
    
    def _combine_scores(self, ai_score: float, signals: Dict[str, float], 
                        normalized: Dict[str, float]) -> float:
        """Комбинируем оценку ИИ с сигналами аномалии (взвешенно)"""
        
        # ИИ получает основной вес (70%)
        ai_weight = 0.70
        
        # Сигналы аномалии - подтверждение (30%)
        signal_weight = 0.30
        signal_score = np.mean(list(signals.values()))
        
        # Итоговая оценка
        combined = (ai_score * ai_weight) + (signal_score * signal_weight)
        
        # Усиливаем, если несколько сигналов активны одновременно
        active_signals = sum(1 for s in signals.values() if s > 0.5)
        if active_signals >= 2:
            # Несколько сигналов = выше уверенность
            combined = min(combined * 1.3, 1.0)
        
        return combined
    
    def _build_formula(self, features: Dict[str, float], signals: Dict[str, float],
                       ai_score: float, final_score: float) -> str:
        """Построить человеко-читаемую формулу расчета"""
        
        iat = features.get('iat', 0)
        entropy = features.get('entropy', 0)
        pkt_len = features.get('packet_len', 0)
        
        # Основная формула
        formula = f"Score = AI({ai_score:.2f}) × 0.70 + Anomaly({np.mean(list(signals.values())):.2f}) × 0.30"
        
        # Добавляем сигналы
        signal_details = []
        if signals['entropy_anomaly'] > 0.5:
            signal_details.append(f"High_Entropy_Low_Len({entropy:.1f}×(1-{pkt_len/65535:.2f}))")
        if signals['rapid_fire'] > 0.5:
            signal_details.append(f"RapidFire(IAT={iat:.7f}s)")
        if signals['syn_only'] > 0.5:
            signal_details.append("SYN_Only_Flag")
        if signals['entropy_extremity'] > 0.5:
            signal_details.append(f"Entropy_Extremity({entropy:.1f})")
        
        if signal_details:
            formula += " | Signals: " + " + ".join(signal_details)
        
        formula += f" = {final_score:.3f}"
        
        return formula
    
    def _fallback_heuristics(self, features: Dict[str, float]) -> Tuple[float, str]:
        """Фаллбэк эвристика, когда ИИ модель недоступна"""
        
        iat = features.get('iat', 0.001)
        entropy = features.get('entropy', 4.0)
        pkt_len = features.get('packet_len', 64)
        
        score = 0.0
        reasons = []
        
        # Показатель 1: Быстрые пакеты
        if iat < 0.00001:
            score += 0.5
            reasons.append(f"RapidFire(IAT<10μs)")
        elif iat < 0.001:
            score += 0.2
        
        # Показатель 2: Высокая энтропия + малый размер пакета
        if entropy > 7.5 and pkt_len < 256:
            score += 0.3
            reasons.append(f"Compressed/Encrypted({entropy:.1f}/{pkt_len}B)")
        elif entropy > 7.0:
            score += 0.15
        
        # Показатель 3: SYN сканирование
        tcp_flags = features.get('tcp_flags', 0)
        if tcp_flags == 0x02:  # Только SYN флаг
            score += 0.3
            reasons.append("SYN_Scan")
        
        formula = f"Heuristic({', '.join(reasons) or 'Normal'}) = {min(score, 1.0):.3f}"
        
        return min(score, 1.0), formula
    
    def update_history(self, confidence: float):
        """Сохранить историю уверенности для анализа"""
        self.confidence_history.append({
            'timestamp': datetime.now().isoformat(),
            'confidence': confidence
        })
        
        # Удерживаем последние 1000 записей
        if len(self.confidence_history) > 1000:
            self.confidence_history = self.confidence_history[-1000:]
