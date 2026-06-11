# 🛡️ AEGIS-NDR v2.0 
## Advanced Network Intrusion Detection & Response System

[![Python 3.10](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Rust](https://img.shields.io/badge/Rust-Latest-orange.svg)](https://www.rust-lang.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue.svg)](https://www.docker.com/)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-green.svg)](#)

Полнофункциональная система обнаружения и предотвращения сетевых атак на основе ИИ с веб-интерфейсом управления и системой автоматического переобучения.

---

## 🚀 Быстрый старт (2 минуты)

```bash
# 1. Запуск
cd /home/lucius/aegis-ndr
docker-compose up --build -d

# 2. Открыть
firefox http://127.0.0.1:8000

# 3. Начать использовать
# Смотрите Alerts → Отправляйте Feedback → Проверяйте Metrics
```

👉 **Полный гайд**: [QUICKSTART.md](./QUICKSTART.md)

---

## ✨ Основные возможности

### 🎯 Обнаружение атак
- ✅ Анализ в реальном времени (10,000+ пакетов/сек)
- ✅ AI модель (Scikit-learn RandomForest)
- ✅ Интеллектуальные эвристики (4 типа аномалий)
- ✅ Комбинированный анализ: AI (70%) + Эвристики (30%)

### 🤖 Система переобучения
- ✅ Сбор feedback'ей через веб-интерфейс
- ✅ Автоматическое переобучение каждый час
- ✅ 5-fold кросс-валидация с вычислением метрик
- ✅ История всех итераций обучения

### 🌐 Веб-интерфейс управления
| Вкладка | Функции |
|---------|---------|
| 📋 **Alerts** | Реал-тайм список обнаруженных атак |
| 📊 **Statistics** | Статистика по типам и IP источникам |
| ✋ **Feedback** | Форма для ручного ввода классификации |
| 🤖 **Training** | Метрики + кнопка переобучения |
| ✅ **Whitelist** | Управление белым списком IP |
| ⚙️ **Config** | Настройка порша и режима блокировки |

### 🔌 REST API (20+ endpoints)
```bash
GET  /api/status              GET  /api/alerts              POST /api/feedback/verdict
GET  /api/stats               POST /api/whitelist           GET  /api/training/metrics
POST /api/training/retrain    GET  /api/config              + более 10 других...
```

---

## 📊 Архитектура системы

```
┌─────────────────────────────────────────────────────┐
│         AEGIS-NDR System Architecture               │
├─────────────────┬──────────────┬────────────────────┤
│                 │              │                    │
│  🔴 CORE        │ 🟢 BRAIN     │ 🟡 EYE             │
│  (Rust)         │ (Python)     │ (FastAPI)          │
│                 │              │                    │
│ • Packet capture│ • AI Model   │ • Web Dashboard    │
│ • Vectorization │ • Heuristics │ • REST API (20+)   │
│ • Caching       │ • Analysis   │ • Feedback form    │
│                 │ • Logging    │                    │
│                 │              │                    │
├─────────────────┴──────────────┴────────────────────┤
│                                                      │
│  🔵 RETRAINER (hourly)                             │
│  • Collect feedback                                 │
│  • Retrain model (5-fold CV)                       │
│  • Save metrics (F1, Precision, Recall)            │
│                                                      │
└──────────────────────────────────────────────────────┘
```

---

## 📈 Как это работает

### 1️⃣ Пакет захватывается
```
Network Traffic → Core (Rust) → 4 features: 
  packet_len (bytes)
  iat (inter-arrival time)
  entropy (0-8)
  tcp_flags (0-63)
```

### 2️⃣ Анализ выполняется
```
Brain (Python) → AI Model (70%) + Heuristics (30%)
→ Confidence score [0-1]
```

### 3️⃣ Decision принимается
```
if confidence > threshold:
  → Log alert
  → Optionally block (if production mode)
```

### 4️⃣ Система учится
```
User feedback → collect_feedback()
→ retrain() (hourly)
→ 5-fold cross-validation
→ F1, Precision, Recall computed
→ Model improved automatically
```

---

## 🎯 Использование

### Day 1-2: Evaluation
```
1. Запустить систему
2. Наблюдать за Alert'ами
3. Отправить 10-20 feedback'ов
4. Запустить переобучение
5. Видеть как F1-score улучшается
```

### Day 3-7: Active Learning
```
1. Ежедневно отправлять feedback (30-50)
2. Балансировать ATTACK и BENIGN примеры
3. Смотреть как F1 растёт к 0.85+
```

### Day 8+: Production
```
1. Когда F1 > 0.90
2. Переключиться на Production Mode
3. Система начнёт активно блокировать атаки
4. Продолжать улучшение через feedback
```

---

## 📚 Документация

| Documento | Назначение |
|-----------|-----------|
| [QUICKSTART.md](./QUICKSTART.md) | 5-минутное введение для новичков |
| [MANAGEMENT.md](./MANAGEMENT.md) | Полное руководство (500+ строк) |
| [README_v2.md](./README_v2.md) | Техническое описание |
| [API_EXAMPLES.py](./API_EXAMPLES.py) | Примеры использования API |
| [IMPLEMENTATION_SUMMARY.md](./IMPLEMENTATION_SUMMARY.md) | Что реализовано |
| [test.sh](./test.sh) | Проверка системы |

---

## 💻 API Примеры

### Получить оповещения:
```bash
curl http://127.0.0.1:8000/api/alerts?limit=10 | jq
```

### Отправить feedback:
```bash
curl -X POST "http://127.0.0.1:8000/api/feedback/verdict?src_ip=192.168.1.100&verdict=ATTACK"
```

### Запустить переобучение:
```bash
curl -X POST http://127.0.0.1:8000/api/training/retrain
```

### Получить метрики:
```bash
curl http://127.0.0.1:8000/api/training/metrics | jq '.current'
```

---

## 📂 Структура данных

```
/app/data/
├── logs/
│   ├── alerts.jsonl          ← Обнаруженные оповещения
│   ├── feedback.jsonl        ← Feedback'и пользователя
│   ├── metrics.json          ← История переобучений
│   └── whitelist.json        ← Белый список IP
└── knowledge/
    └── ai1_model.pkl         ← Сохранённая модель ML
```

---

## ⚠️ Требования

- **OS**: Linux (для libpcap)
- **Docker**: 20.10+
- **Docker Compose**: 1.29+
- **RAM**: 2GB+ (рекомендуется 4GB+)
- **CPU**: 2+ ядра

---

## 🔧 Управление системой

```bash
# Запуск
docker-compose up --build -d

# Статус
docker-compose ps

# Логи
docker-compose logs -f brain
docker-compose logs -f eye
docker-compose logs -f retrainer

# Остановка
docker-compose down

# Очистка
docker-compose down -v
```

---

## 🎓 Ожидаемые результаты

| День | F1-Score | Состояние | Действие |
|------|----------|-----------|---------|
| 1-2 | 0.55 | Learning | Отправлять feedback |
| 3-5 | 0.75 | Improving | Продолжать feedback |
| 6-7 | 0.85 | Ready | Готово к тестированию |
| 8+ | 0.92+ | Production | Включить блокировку |

---

## 🚨 Troubleshooting

### Не могу подключиться к API
```bash
docker-compose ps
docker-compose logs eye
```

### F1-score не растёт
- Отправляйте минимум 50 примеров
- Проверьте что feedback'и правильные
- Балансируйте ATTACK и BENIGN классы

### Блокировка не работает
- Проверьте Block Mode (должен быть "production")
- F1 должна быть > 0.80
- Контейнер должен быть привилегированным

Полное руководство: [MANAGEMENT.md](./MANAGEMENT.md)

---

## ✅ Что работает

- ✅ Захват пакетов в реальном времени
- ✅ Анализ на основе AI + эвристик
- ✅ Веб-интерфейс управления (полный)
- ✅ REST API для интеграции
- ✅ Система feedback'ей
- ✅ Автоматическое переобучение (hourly)
- ✅ Метрики (F1, Precision, Recall)
- ✅ Белый список IP
- ✅ Статистика атак
- ✅ Shadow/Production режимы

---

## 📞 Поддержка

- 📖 Docs: [MANAGEMENT.md](./MANAGEMENT.md)
- 🏃 Quick: [QUICKSTART.md](./QUICKSTART.md)
- 💻 Tech: [README_v2.md](./README_v2.md)
- 🔌 API: [API_EXAMPLES.py](./API_EXAMPLES.py)

---

```
╔════════════════════════════════════════════╗
║    Ready to protect your network?          ║
║    docker-compose up                       ║
║    http://127.0.0.1:8000                  ║
╚════════════════════════════════════════════╝
```

**AEGIS-NDR v2.0** | Production Ready | 2025-01-15

2. **Brain анализирует через IntelligentHeuristics**
   - Нормализация признаков
   - Извлечение аномальных сигналов
   - ИИ-классификация (70%)
   - Сигналы (30%)
   - Формула: `Score = AI(0.45) × 0.70 + Signals(0.60) × 0.30 = 0.465`

3. **Вердикт с порогом 0.75**
   - Высокий риск: > 0.75 → ALERT
   - Подозрительно: 0.50-0.75 → WARN
   - Норма: < 0.50 → OK

4. **Логирование в alerts.jsonl**
   ```json
   {
     "timestamp": "2026-05-12T03:05:00.123456",
     "src_ip": "192.168.1.100",
     "confidence": 0.824,
     "features": {"packet_len": 256, "iat": 0.00001, "entropy": 7.8, "tcp_flags": 2},
     "analysis": "Score = AI(0.82) × 0.70 + Signals(0.85) × 0.30 | RapidFire + SYN_Only = 0.824",
     "type": "MALICIOUS_TRAFFIC"
   }
   ```

## 🚀 Запуск системы

### 1. Сборка
```bash
cd /home/lucius/aegis-ndr
docker compose build
```

### 2. Запуск
```bash
docker compose up -d
```

Контейнеры:
- **brain** - порт 50051 (gRPC)
- **core** - захват пакетов на wlp3s0
- **eye** - порт 8000 (REST API)

### 3. Проверка логов
```bash
# Brain анализирует
docker compose logs brain -f

# Core получает пакеты
docker compose logs core -f

# Eye API
docker compose logs eye -f
```

## 🔍 Тестирование атак

### Режимы работы

**ShadowMode** (дефолт - не блокирует реально)
```bash
docker compose up
```
Логирует, но не блокирует. Идеально для тестирования.

**Production** (включить блокировку)
Отредактировать docker-compose.yml:
```yaml
core:
  environment:
    - BLOCK_MODE=production
```

### Примеры атак для тестирования

#### 1. Rapid-Fire Attack (DoS-подобная)
```bash
# Очень быстрые пакеты (< 1 миллисекунда между ними)
for i in {1..1000}; do
  timeout 0.1 bash -c "echo 'attack' | nc -u 192.168.1.1 80" 2>/dev/null &
done
wait
```

**Ожидаемый результат**:
- IntelligentHeuristics обнаружит `RapidFire(IAT<1ms)`
- Сигнал: 0.8, Confidence: высокая (> 0.75)
- ALERT в логе

#### 2. Port Scanning (SYN-only)
```bash
nmap -sS 192.168.1.1
```

**Ожидаемый результат**:
- Обнаружение: `SYN_Only_Flag`
- Сигнал активирует anomaly detection
- ALERT в логе

#### 3. High-Entropy Attack (зашифрованная/сжатая атака)
```bash
# Генерируем трафик высокой энтропии
python3 -c "import random; data = bytes(random.getrandbits(8) for _ in range(1000)); 
import socket; s = socket.socket(); s.connect(('192.168.1.1', 443)); 
s.send(data * 100); s.close()"
```

**Ожидаемый результат**:
- Обнаружение: `Entropy_Anomaly`, `Entropy_Extremity`
- Комбинированный сигнал
- ALERT в логе

## 📊 Анализ результатов

### Просмотр alerts
```bash
docker compose exec core cat /app/data/logs/alerts.jsonl | jq .
```

### Пример вывода Brain при атаке
```
brain-1 | [*] Brain[192.168.1.100]: Score = AI(0.82) × 0.70 + Anomaly(0.85) × 0.30 | Signals: RapidFire(IAT=0.00001s) + SYN_Only_Flag + Entropy_Extremity = 0.824
brain-1 | [ALERT] 🚨 Запись атаки в лог: 192.168.1.100 (conf=0.824)
```

### Пример вывода Core при атаке
```
core-1 | [OK] ✓ IP 192.168.1.100 признан легитимным
```
(Если > 0.75, то будет ALERT, но в shadow mode не блокирует)

## 🧠 Обучение модели

### Online Learning (автоматический)
При каждом пакете модель онлайн обновляется:
- AI1 (ARFClassifier) учится классифицировать
- AI2 (VAE) запоминает паттерны нормы

### Batch Training (явный)
```python
from training.online import OnlineTrainer

trainer = OnlineTrainer()

# Тренировка на датасете
trainer.train_batch('/app/data/datasets/my_dataset.csv')

# Сбалансированная тренировка
trainer.train_balanced('/app/data/datasets/')
```

## ⚙️ Конфигурация

### Переменные окружения
- `IFACE=wlp3s0` - сетевой интерфейс
- `BRAIN_ADDR=http://127.0.0.1:50051` - адрес Brain
- `BLOCK_MODE=shadow` - режим (shadow/production)
- `CONFIDENCE_THRESHOLD=0.75` - порог чувствительности

### Файлы конфигурации
- `core/Cargo.toml` - dependencies
- `brain/requirements.txt` - Python deps
- `shared/proto/aegis.proto` - Protocol Buffers

## 📈 Метрики и события

### Основные метрики
- **Packet processed**: Всего пакетов обработано
- **Confidence histogram**: Распределение уровней уверенности
- **Signal triggercount**: Сколько раз активировался каждый сигнал
- **Training progress**: Шаги обучения моделей

### Типы событий
- INFO: Нормальные операции
- WARN: Подозрительная активность (0.50-0.75)
- ALERT: Атака обнаружена (> 0.75)
- ERROR: Критические ошибки

## 🔧 Troubleshooting

### Ошибка: `predict_proba not found`
**Решение**: Убедитесь что используется правильная версия river
```bash
pip list | grep river
# Должно быть river==0.15.0
```

### Ошибка: `Iface not found`
**Решение**: Проверьте имя интерфейса
```bash
ip a  # Найдите правильное имя
docker compose down
docker compose up -e IFACE=eth0
```

### Модель не обновляется
**Решение**: Проверьте permissions на /app/data/knowledge/
```bash
docker compose exec brain ls -la /app/data/knowledge/
```

## 📚 Дополнительно

- [Protocol Buffers](../shared/proto/aegis.proto)
- [Learning System](./src/training/online.py)
- [Heuristics](./src/learning.py)
