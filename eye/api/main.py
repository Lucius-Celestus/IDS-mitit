"""
AEGIS-NDR Eye API - Веб-интерфейс управления системой обнаружения атак
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import json
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import threading
import time

# Импортировать ModelTrainer для работы с переобучением
sys.path.insert(0, '/app/src')
try:
    from training import ModelTrainer
except ImportError:
    ModelTrainer = None

app = FastAPI(title="AEGIS-NDR Control Panel", version="2.0")

# Конфигурация путей (должны быть ДО middleware!)
ALERTS_FILE = "/app/data/logs/alerts.jsonl"
FEEDBACK_FILE = "/app/data/logs/feedback.jsonl"
PACKETS_FILE = "/app/data/logs/packets.jsonl"  # Все пакеты/HTTP запросы
METRICS_FILE = "/app/data/logs/metrics.json"
WHITELIST_FILE = "/app/data/logs/whitelist.json"
CONFIG_FILE = "/app/data/config.json"

# CORS для локальных запросов
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Логирование всех пакетов
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

class PacketLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Логируем пакет
        packet = {
            "timestamp": datetime.now().isoformat(),
            "client_ip": request.client.host if request.client else "unknown",
            "method": request.method,
            "path": request.url.path,
            "query": str(request.url.query) if request.url.query else "",
            "status": 0
        }
        
        # Логируем headers
        try:
            packet["headers"] = dict(request.headers)
        except:
            packet["headers"] = {}
        
        # Выполняем запрос
        response = await call_next(request)
        packet["status"] = response.status_code
        
        # Сохраняем пакет
        try:
            os.makedirs(os.path.dirname(PACKETS_FILE), exist_ok=True)
            with open(PACKETS_FILE, 'a') as f:
                f.write(json.dumps(packet) + '\n')
        except:
            pass
        
        return response

app.add_middleware(PacketLoggingMiddleware)

# Глобальная конфигурация
CONFIG = {
    "alert_threshold": 0.5,
    "block_mode": "shadow",  # shadow или production
    "auto_retrain": True,
    "feedback_required": False
}

# Инициализировать файлы
for path in [WHITELIST_FILE]:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    if not os.path.exists(path) and path == WHITELIST_FILE:
        with open(path, 'w') as f:
            json.dump([], f)

# Загрузить конфигурацию
if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE) as f:
        CONFIG.update(json.load(f))


def save_config():
    """Сохранить конфигурацию"""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(CONFIG, f, indent=2)


def load_alerts(limit: int = 100) -> List[Dict]:
    """Загрузить последние оповещения"""
    if not os.path.exists(ALERTS_FILE):
        return []
    
    alerts = []
    try:
        with open(ALERTS_FILE) as f:
            for line in f:
                if line.strip():
                    alerts.append(json.loads(line))
    except:
        pass
    
    return sorted(alerts, key=lambda x: x.get('timestamp', ''), reverse=True)[:limit]


def load_metrics() -> Dict:
    """Загрузить метрики модели"""
    if not os.path.exists(METRICS_FILE):
        return {"status": "no_training", "history": []}
    
    try:
        with open(METRICS_FILE) as f:
            history = json.load(f)
        
        if not history:
            return {"status": "no_training", "history": []}
        
        current = history[-1]
        best = max(history, key=lambda x: x.get('f1', 0))
        
        return {
            "status": "trained",
            "current": current,
            "best": best,
            "history": history[-10:],
            "total_iterations": len(history)
        }
    except:
        return {"status": "error", "history": []}


def get_whitelist() -> List[str]:
    """Получить список белых IP-адресов"""
    if not os.path.exists(WHITELIST_FILE):
        return []
    
    try:
        with open(WHITELIST_FILE) as f:
            return json.load(f)
    except:
        return []


def save_whitelist(ips: List[str]):
    """Сохранить список белых IP-адресов"""
    with open(WHITELIST_FILE, 'w') as f:
        json.dump(sorted(set(ips)), f, indent=2)


# ============================================================
# REST API ENDPOINTS
# ============================================================

@app.get("/api/status")
async def get_status():
    """Получить статус системы"""
    alerts = load_alerts(1000)
    high_conf = len([a for a in alerts if a.get('confidence', 0) > 0.7])
    
    # Получить количество пакетов из файла
    try:
        with open(PACKETS_FILE) as f:
            total_packets = sum(1 for _ in f)
    except:
        total_packets = 0
    
    return {
        "status": "OPERATIONAL",
        "total_alerts": len(alerts),
        "high_confidence": high_conf,
        "total_packets": total_packets,
        "block_mode": CONFIG.get('block_mode', 'shadow'),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/packets")
async def get_packets(limit: int = Query(50, le=500)):
    """Получить последние пакеты/HTTP запросы"""
    if not os.path.exists(PACKETS_FILE):
        return {"total": 0, "packets": [], "timestamp": datetime.now().isoformat()}
    
    packets = []
    try:
        with open(PACKETS_FILE) as f:
            for line in f:
                if line.strip():
                    packets.append(json.loads(line))
    except:
        pass
    
    packets = sorted(packets, key=lambda x: x.get('timestamp', ''), reverse=True)[:limit]
    return {"total": len(packets), "packets": packets, "timestamp": datetime.now().isoformat()}


@app.get("/api/alerts")
async def get_alerts(
    limit: int = Query(50, le=500),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0)
):
    """Получить список оповещений"""
    alerts = load_alerts(limit * 2)
    filtered = [
        a for a in alerts 
        if a.get('confidence', 0) >= min_confidence
    ][:limit]
    
    return {
        "total": len(filtered),
        "alerts": filtered,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/alerts/{ip}")
async def get_alerts_by_ip(ip: str, limit: int = Query(20, le=100)):
    """Получить оповещения по конкретному IP"""
    alerts = load_alerts(500)
    filtered = [a for a in alerts if a.get('src_ip') == ip][:limit]
    
    return {
        "ip": ip,
        "count": len(filtered),
        "alerts": filtered
    }


@app.get("/api/stats")
async def get_statistics():
    """Получить статистику атак"""
    alerts = load_alerts(1000)
    
    by_type = {}
    by_ip = {}
    hourly = {}
    
    for alert in alerts:
        # По типу
        attack_type = alert.get('attack_type', 'UNKNOWN')
        by_type[attack_type] = by_type.get(attack_type, 0) + 1
        
        # По исходящему IP
        src_ip = alert.get('src_ip', 'UNKNOWN')
        by_ip[src_ip] = by_ip.get(src_ip, 0) + 1
        
        # По часам
        try:
            ts = alert.get('timestamp', '')
            if ts and len(ts) > 13:
                hour = ts[:13] + ":00:00"
                hourly[hour] = hourly.get(hour, 0) + 1
        except:
            pass
    
    top_ips = sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:10]
    top_types = sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:5]
    
    return {
        "total_alerts": len(alerts),
        "attack_types": dict(top_types),
        "top_sources": dict(top_ips),
        "hourly": dict(sorted(hourly.items(), reverse=True)[:24]),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/whitelist")
async def get_whitelist_api():
    """Получить список белых IP-адресов"""
    return {
        "whitelist": get_whitelist(),
        "count": len(get_whitelist())
    }


@app.post("/api/whitelist")
async def add_to_whitelist(ip: str):
    """Добавить IP в белый список"""
    whitelist = get_whitelist()
    if ip not in whitelist:
        whitelist.append(ip)
        save_whitelist(whitelist)
    
    return {"status": "added", "whitelist": whitelist}


@app.delete("/api/whitelist/{ip}")
async def remove_from_whitelist(ip: str):
    """Удалить IP из белого списка"""
    whitelist = get_whitelist()
    if ip in whitelist:
        whitelist.remove(ip)
        save_whitelist(whitelist)
    
    return {"status": "removed", "whitelist": whitelist}


@app.post("/api/feedback/verdict")
async def submit_verdict(
    src_ip: str,
    verdict: str,  # "ATTACK" или "BENIGN"
    features: Dict = None,
    confidence: float = None
):
    """Отправить ручное решение для переобучения"""
    if verdict not in ["ATTACK", "BENIGN"]:
        raise HTTPException(status_code=400, detail="Verdict must be ATTACK or BENIGN")
    
    feedback = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": src_ip,
        "verdict": verdict,
        "features": features or {},
        "confidence": confidence,
        "_used": False
    }
    
    os.makedirs(os.path.dirname(FEEDBACK_FILE), exist_ok=True)
    with open(FEEDBACK_FILE, 'a') as f:
        f.write(json.dumps(feedback) + '\n')
    
    return {"status": "received", "feedback_id": feedback.get("timestamp")}


@app.get("/api/training/metrics")
async def get_training_metrics():
    """Получить метрики переобучения модели"""
    metrics = load_metrics()
    return metrics


@app.post("/api/training/retrain")
async def trigger_retraining(force: bool = False):
    """Запустить переобучение модели"""
    if ModelTrainer is None:
        raise HTTPException(status_code=500, detail="ModelTrainer not available")
    
    try:
        trainer = ModelTrainer()
        result = trainer.retrain(force=force)
        
        return {
            "status": "success" if result.get('success') else "skipped",
            "result": result,
            "metrics": load_metrics()
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


@app.get("/api/config")
async def get_config():
    """Получить текущую конфигурацию"""
    return CONFIG


@app.post("/api/config")
async def update_config(updates: Dict):
    """Обновить конфигурацию"""
    for key, value in updates.items():
        if key in CONFIG:
            CONFIG[key] = value
    
    save_config()
    return {"status": "updated", "config": CONFIG}


# ============================================================
# WEB INTERFACE
# ============================================================

HTML_DASHBOARD = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AEGIS-NDR Control Panel</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            min-height: 100vh;
        }
        
        .header {
            background: rgba(10, 10, 30, 0.8);
            border-bottom: 2px solid #00ff88;
            padding: 20px;
            backdrop-filter: blur(10px);
        }
        
        .header h1 {
            font-size: 28px;
            color: #00ff88;
            text-shadow: 0 0 10px #00ff88;
            margin-bottom: 10px;
            font-weight: 700;
        }
        
        .header p {
            color: #aaa;
            font-size: 14px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .status-bar {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .status-card {
            background: rgba(30, 40, 60, 0.9);
            border: 1px solid #00ff88;
            border-radius: 10px;
            padding: 20px;
            backdrop-filter: blur(10px);
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.1);
        }
        
        .status-card h3 {
            color: #00ff88;
            font-size: 12px;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        
        .status-card .value {
            font-size: 32px;
            font-weight: bold;
            color: #00ff88;
        }
        
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 1px solid rgba(0, 255, 136, 0.2);
            overflow-x: auto;
        }
        
        .tab-button {
            padding: 12px 20px;
            background: transparent;
            border: none;
            color: #aaa;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            border-bottom: 2px solid transparent;
            transition: all 0.3s;
            white-space: nowrap;
        }
        
        .tab-button.active {
            color: #00ff88;
            border-bottom-color: #00ff88;
            text-shadow: 0 0 10px #00ff88;
        }
        
        .tab-button:hover {
            color: #00ff88;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .alerts-list {
            max-height: 600px;
            overflow-y: auto;
            background: rgba(30, 40, 60, 0.9);
            border: 1px solid #00ff88;
            border-radius: 10px;
            padding: 0;
        }
        
        .alert-item {
            padding: 15px;
            border-bottom: 1px solid rgba(0, 255, 136, 0.2);
            display: flex;
            justify-content: space-between;
            align-items: center;
            hover: rgba(0, 255, 136, 0.05);
            transition: all 0.3s;
        }
        
        .alert-item:hover {
            background: rgba(0, 255, 136, 0.05);
        }
        
        .alert-info {
            flex: 1;
        }
        
        .alert-ip {
            color: #ff6b6b;
            font-weight: bold;
            font-size: 14px;
        }
        
        .alert-type {
            color: #aaa;
            font-size: 12px;
            margin-top: 5px;
        }
        
        .alert-confidence {
            color: #00ff88;
            font-weight: bold;
            font-size: 12px;
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .metric-box {
            background: rgba(30, 40, 60, 0.9);
            border: 1px solid #00ff88;
            border-radius: 10px;
            padding: 20px;
        }
        
        .metric-box h3 {
            color: #00ff88;
            font-size: 14px;
            margin-bottom: 15px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .metric-value {
            font-size: 24px;
            font-weight: bold;
            color: #00ff88;
            margin-bottom: 5px;
        }
        
        .metric-label {
            color: #aaa;
            font-size: 12px;
        }
        
        input, select, button {
            background: rgba(50, 60, 90, 0.9);
            color: #e0e0e0;
            border: 1px solid #00ff88;
            padding: 10px 15px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.3s;
        }
        
        input:focus, select:focus {
            outline: none;
            border-color: #00ffff;
            box-shadow: 0 0 10px rgba(0, 255, 255, 0.3);
        }
        
        button {
            background: rgba(0, 255, 136, 0.1);
            font-weight: 600;
            color: #00ff88;
            cursor: pointer;
            border: 1px solid #00ff88;
        }
        
        button:hover {
            background: rgba(0, 255, 136, 0.2);
            text-shadow: 0 0 10px #00ff88;
        }
        
        .form-group {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }
        
        .loading {
            display: inline-block;
            width: 12px;
            height: 12px;
            border: 2px solid rgba(0, 255, 136, 0.3);
            border-radius: 50%;
            border-top-color: #00ff88;
            animation: spin 0.8s linear infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .chart {
            background: rgba(30, 40, 60, 0.9);
            border: 1px solid #00ff88;
            border-radius: 10px;
            padding: 20px;
            margin-top: 20px;
            min-height: 200px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AEGIS-NDR Control Panel</h1>
        <p>Advanced Threat Detection & Response System | Status: <span id="status" style="color: #00ff88;">OPERATIONAL</span></p>
    </div>
    
    <div class="container">
        <!-- Status Bar -->
        <div class="status-bar">
            <div class="status-card">
                <h3>Total Alerts</h3>
                <div class="value" id="total-alerts">0</div>
            </div>
            <div class="status-card">
                <h3>High Confidence</h3>
                <div class="value" id="high-confidence">0</div>
            </div>
            <div class="status-card">
                <h3>Block Mode</h3>
                <div class="value" id="block-mode">SHADOW</div>
            </div>
            <div class="status-card">
                <h3>Model F1-Score</h3>
                <div class="value" id="f1-score">--</div>
            </div>
        </div>
        
        <!-- Tabs -->
        <div class="tabs">
            <button class="tab-button active" onclick="switchTab('alerts')">📋 Alerts & Feedback</button>
            <button class="tab-button" onclick="switchTab('packets')">📡 All Packets</button>
            <button class="tab-button" onclick="switchTab('stats')">📊 Statistics</button>
            <button class="tab-button" onclick="switchTab('training')">🤖 Training</button>
            <button class="tab-button" onclick="switchTab('whitelist')">✅ Whitelist</button>
            <button class="tab-button" onclick="switchTab('config')">⚙️ Configuration</button>
        </div>
        
        <!-- Alerts Tab (with integrated Feedback) -->
        <div id="alerts" class="tab-content active">
            <div style="margin-bottom: 20px;">
                <h3>🎯 Alert Analysis & Manual Verdict</h3>
                <p style="color: #aaa; font-size: 12px;">Click on any alert below to analyze it, or use the buttons to provide manual feedback for model training.</p>
            </div>
            <div class="alerts-list" id="alerts-list">
                <div class="alert-item">
                    <div class="alert-info">
                        <div class="alert-ip">Loading...</div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Packets Tab (All HTTP requests and packets) -->
        <div id="packets" class="tab-content">
            <div style="margin-bottom: 20px;">
                <h3>🌐 Network Packets & HTTP Requests</h3>
                <p style="color: #aaa; font-size: 12px;">Real-time view of all network packets and HTTP requests to the system. Auto-refreshes every 2 seconds.</p>
                <button onclick="loadPackets()" style="background: rgba(0,255,136,0.2); border: 1px solid #00ff88; color: #00ff88; padding: 8px 15px; border-radius: 4px; cursor: pointer;">🔄 Refresh Now</button>
            </div>
            <div id="packets-list" style="display: flex; flex-direction: column; gap: 10px;">
                <div style="padding: 20px; color: #aaa; text-align: center;">Loading packets...</div>
            </div>
        </div>
        
        <!-- Statistics Tab -->
        <div id="stats" class="tab-content">
            <div class="metrics-grid">
                <div class="metric-box">
                    <h3>Top Attack Types</h3>
                    <div id="attack-types"></div>
                </div>
                <div class="metric-box">
                    <h3>Top Source IPs</h3>
                    <div id="top-ips"></div>
                </div>
            </div>
        </div>
        

        
        <!-- Training Tab -->
        <div id="training" class="tab-content">
            <div class="metric-box">
                <h3>Model Training Metrics</h3>
                <button onclick="triggerRetraining()">🔄 Force Retraining</button>
                <div id="training-metrics" style="margin-top: 20px;"></div>
            </div>
        </div>
        
        <!-- Whitelist Tab -->
        <div id="whitelist" class="tab-content">
            <div class="metric-box">
                <h3>Add to Whitelist</h3>
                <div class="form-group">
                    <input type="text" id="whitelist-ip" placeholder="IP Address to Whitelist" />
                    <button onclick="addToWhitelist()">+ Add</button>
                </div>
            </div>
            <div class="metric-box" style="margin-top: 20px;">
                <h3>Current Whitelist</h3>
                <div id="whitelist-list"></div>
            </div>
        </div>
        
        <!-- Config Tab -->
        <div id="config" class="tab-content">
            <div class="metric-box">
                <h3>System Configuration</h3>
                <div class="form-group">
                    <label>Alert Threshold:</label>
                    <input type="number" id="alert-threshold" min="0" max="1" step="0.1" />
                    <button onclick="updateConfig()">Save</button>
                </div>
                <div class="form-group">
                    <label>Block Mode:</label>
                    <select id="block-mode-select">
                        <option value="shadow">Shadow (Log Only)</option>
                        <option value="production">Production (Actual Block)</option>
                    </select>
                </div>
            </div>
        </div>
    </div>
    
    <script type="text/javascript">
        function switchTab(name) { document.querySelectorAll('.tab-content').forEach(e => e.classList.remove('active')); document.getElementById(name).classList.add('active'); }
        function loadStatus() { fetch('/api/status').then(r => r.json()).then(d => { document.getElementById('total-alerts').textContent = d.total_alerts; }); }
        function loadPackets() { fetch('/api/packets?limit=100').then(r => r.json()).then(d => { document.getElementById('packets-list').innerHTML = (d.packets || []).slice(0, 30).map(p => '<div style="padding:10px;background:rgba(255,255,255,0.05);margin:5px 0;border-radius:4px">' + p.method + ' ' + p.path + ' - ' + p.status + '</div>').join(''); }); }
        function loadAlerts() { fetch('/api/alerts?limit=30').then(r => r.json()).then(d => { document.getElementById('alerts-list').innerHTML = (d.alerts || []).map(a => '<div style="padding:10px;background:rgba(255,68,68,0.1);margin:5px 0;border-radius:4px">' + a.src_ip + ' - Confidence: ' + (a.confidence * 100).toFixed(1) + '%</div>').join(''); }); }
        function loadStatistics() { fetch('/api/stats').then(r => r.json()).then(d => { document.getElementById('attack-types').innerHTML = Object.entries(d.attack_types || {}).map(e => '<div>' + e[0] + ': ' + e[1] + '</div>').join(''); }); }
        function loadWhitelist() { fetch('/api/whitelist').then(r => r.json()).then(d => { document.getElementById('whitelist-list').innerHTML = (d.whitelist || []).map(ip => '<div style="padding:8px;background:rgba(0,255,136,0.1);margin:5px 0;border-radius:4px">' + ip + '</div>').join(''); }); }
        function loadTrainingMetrics() { fetch('/api/training/metrics').then(r => r.json()).then(d => { document.getElementById('training-metrics').innerHTML = (d && d.current) ? '<p>F1-Score: ' + (d.current.f1 * 100).toFixed(1) + '%</p>' : '<p>No training data</p>'; }); }
        function loadConfig() { fetch('/api/config').then(r => r.json()).then(d => { document.getElementById('alert-threshold').value = d.alert_threshold || 0.5; }); }
        function init() { loadStatus(); setTimeout(loadAlerts, 100); setTimeout(loadPackets, 500); }
        if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', init); } else { init(); }
    </script>
        
        <!-- Alerts Tab -->
                .then(r => r.json())
                .then(d => {
                    alertsData = d.alerts;
                    const html = d.alerts.map((a, idx) => {
                        const borderColor = a.confidence > 0.7 ? '#ff4444' : '#ffaa44';
                        const port = a.dest_port || '--';
                        const type = a.type || 'HYBRID_AI_DETECTION';
                        const confidence = (a.confidence * 100).toFixed(1);
                        const time = new Date(a.timestamp).toLocaleTimeString();
                        const ip = a.src_ip;
                        
                        let row = '<div class="alert-item" style="display: flex; flex-direction: column; padding: 15px; border-left: 4px solid ' + borderColor + '; position: relative;">';
                        row += '<div class="alert-info" style="margin-bottom: 10px;">';
                        row += '<div class="alert-ip" style="font-weight: bold; margin-bottom: 5px;">🔴 ' + ip + '</div>';
                        row += '<div style="font-size: 12px; color: #aaa; margin-bottom: 8px;">';
                        row += '<span>Port: ' + port + '</span> • ';
                        row += '<span>Type: ' + type + '</span> • ';
                        row += '<span>' + time + '</span>';
                        row += '</div>';
                        row += '<div style="background: rgba(255,68,68,0.1); padding: 8px; border-radius: 4px; margin: 5px 0;">';
                        row += '<span style="color: #ffaa44;">Confidence: <strong>' + confidence + '%</strong></span>';
                        row += '</div></div>';
                        row += '<div style="display: flex; gap: 8px; margin-top: 8px;">';
                        row += '<button onclick="submitVerdictForAlert(' + idx + ', \'BENIGN\')" ';
                        row += 'style="flex: 1; background: rgba(0,255,136,0.15); border: 1px solid #00ff88; color: #00ff88; padding: 8px; border-radius: 4px; cursor: pointer; font-size: 11px; transition: all 0.2s;">';
                        row += '✓ Benign</button>';
                        row += '<button onclick="submitVerdictForAlert(' + idx + ', \'ATTACK\')" ';
                        row += 'style="flex: 1; background: rgba(255,68,68,0.15); border: 1px solid #ff4444; color: #ff4444; padding: 8px; border-radius: 4px; cursor: pointer; font-size: 11px; transition: all 0.2s;">';
                        row += '✗ Attack</button></div></div>';
                        return row;
                    }).join('');
                    document.getElementById('alerts-list').innerHTML = html || '<div style="padding: 20px; color: #aaa;">No alerts found</div>';
                });
        }
        
        function getStatusColor(status) {
            if (status >= 200 && status < 300) return '#00ff88';  // Зеленый - успех
            if (status >= 300 && status < 400) return '#ffaa44';  // Оранжевый - редирект
            if (status >= 400 && status < 500) return '#ff6b6b';  // Красный - клиент ошибка
            if (status >= 500) return '#ff4444';                   // Темно-красный - сервер ошибка
            return '#aaa';                                         // Серый - неизвестно
        }
        
        function getMethodColor(method) {
            switch(method) {
                case 'GET': return '#00ff88';      // Зеленый
                case 'POST': return '#ffaa44';     // Оранжевый  
                case 'PUT': return '#6b9aff';      // Синий
                case 'DELETE': return '#ff6b6b';   // Красный
                case 'OPTIONS': return '#aaa';     // Серый
                default: return '#ccc';             // Светло-серый
            }
        }
        
        // Global packets storage for details display
        let currentPackets = [];
        
        function loadPackets() {
            fetch('/api/packets?limit=100')
                .then(r => r.json())
                .then(d => {
                    currentPackets = d.packets;
                    const html = d.packets.map((p, idx) => {
                        const color = getStatusColor(p.status);
                        const methodColor = getMethodColor(p.method);
                        const time = new Date(p.timestamp).toLocaleTimeString();
                        const path = p.path + (p.query ? '?' + p.query : '');
                        
                        return '<div style="display:flex;padding:12px;background:rgba(255,255,255,0.05);border-left:4px solid ' + color + ';border-radius:4px;gap:15px;align-items:center">' +
                            '<div style="min-width:60px;text-align:center">' +
                            '<span style="display:inline-block;background:' + methodColor + ';color:#000;padding:4px 8px;border-radius:3px;font-size:11px;font-weight:bold">' + p.method + '</span>' +
                            '</div>' +
                            '<div style="flex:1;min-width:0">' +
                            '<div style="color:#aaa;font-size:11px;margin-bottom:4px">🌐 ' + p.client_ip + ' → Status: <span style="color:' + color + ';font-weight:bold">' + p.status + '</span></div>' +
                            '<div style="color:#00ff88;font-size:12px;word-break:break-all"><strong>' + p.path + '</strong>' + (p.query ? '?' + p.query : '') + '</div>' +
                            '<div style="color:#aaa;font-size:10px;margin-top:4px">' + time + '</div>' +
                            '</div>' +
                            '<button onclick="showPacketDetails(' + idx + ')" style="background:rgba(107,154,255,0.2);border:1px solid #6b9aff;color:#6b9aff;padding:6px 12px;border-radius:3px;cursor:pointer;font-size:10px;white-space:nowrap">📄 Details</button>' +
                            '</div>';
                    }).join('');
                    
                    document.getElementById('packets-list').innerHTML = html || '<div style="padding:20px;color:#aaa;text-align:center">No packets found</div>';
                });
        }
        
        function showPacketDetails(idx) {
            const p = currentPackets[idx];
            if (!p) {
                alert('Packet not found');
                return;
            }
            const details = 'Timestamp: ' + p.timestamp + '\n' +
                          'Client IP: ' + p.client_ip + '\n' +
                          'Method: ' + p.method + '\n' +
                          'Path: ' + p.path + '\n' +
                          'Query: ' + (p.query || '(none)') + '\n' +
                          'Status: ' + p.status + '\n' +
                          'Headers: ' + JSON.stringify(p.headers, null, 2);
            alert('Packet Details:\n\n' + details);
        }
        
        // Auto-refresh packets tab every 2 seconds when visible
        setInterval(() => {
            if (document.getElementById('packets').classList.contains('active')) {
                loadPackets();
            }
        }, 2000);
        
        function loadStatistics() {
            fetch('/api/stats')
                .then(r => r.json())
                .then(d => {
                    const types = Object.entries(d.attack_types).map(([k,v]) => `<div>${k}: ${v}</div>`).join('');
                    const ips = Object.entries(d.top_sources).map(([k,v]) => `<div>${k}: ${v}</div>`).join('');
                    document.getElementById('attack-types').innerHTML = types;
                    document.getElementById('top-ips').innerHTML = ips;
                });
        }
        
        function loadTrainingMetrics() {
            fetch('/api/training/metrics')
                .then(r => r.json())
                .then(d => {
                    let html = '';
                    if (d.status === 'trained' && d.current) {
                        const f1 = (d.current.f1 * 100).toFixed(2);
                        const precision = (d.current.precision * 100).toFixed(2);
                        const recall = (d.current.recall * 100).toFixed(2);
                        const timestamp = new Date(d.current.timestamp).toLocaleString();
                        const samples = d.current.samples;
                        
                        html = '<div style="color: #00ff88; margin-top: 10px;">' +
                            '<p><strong>F1-Score:</strong> ' + f1 + '%</p>' +
                            '<p><strong>Precision:</strong> ' + precision + '%</p>' +
                            '<p><strong>Recall:</strong> ' + recall + '%</p>' +
                            '<p><strong>Last Training:</strong> ' + timestamp + '</p>' +
                            '<p><strong>Samples Used:</strong> ' + samples + '</p>' +
                            '</div>';
                        document.getElementById('f1-score').textContent = (d.current.f1 * 100).toFixed(1) + '%';
                    } else {
                        html = '<p style="color: #aaa;">No training data yet</p>';
                        document.getElementById('f1-score').textContent = '--';
                    }
                    document.getElementById('training-metrics').innerHTML = html;
                });
        }
        
        function triggerRetraining() {
            const btn = event.target;
            btn.disabled = true;
            btn.innerHTML = '<span class="loading"></span> Retraining...';
            
            fetch('/api/training/retrain', {method: 'POST'})
                .then(r => r.json())
                .then(d => {
                    btn.disabled = false;
                    btn.innerHTML = '🔄 Force Retraining';
                    alert('Retraining result: ' + d.status);
                    loadTrainingMetrics();
                });
        }
        
        function submitVerdictFromAlert(ip, verdict) {
            if (!ip) {
                alert('No IP address!');
                return;
            }
            
            // Visual feedback
            const btn = event.target;
            const originalText = btn.textContent;
            btn.textContent = '⏳ Sending...';
            btn.disabled = true;
            
            fetch('/api/feedback/verdict?src_ip=' + ip + '&verdict=' + verdict, {method: 'POST'})
                .then(r => r.json())
                .then(d => {
                    btn.textContent = '✓ Sent!';
                    setTimeout(() => {
                        btn.textContent = originalText;
                        btn.disabled = false;
                    }, 1500);
                })
                .catch(e => {
                    btn.textContent = '✗ Error';
                    btn.disabled = false;
                    setTimeout(() => {
                        btn.textContent = originalText;
                    }, 2000);
                });
        }
        
        function addToWhitelist() {
            const ip = document.getElementById('whitelist-ip').value;
            if (!ip) {
                alert('Please enter IP address');
                return;
            }
            
            fetch('/api/whitelist?ip=' + ip, {method: 'POST'})
                .then(r => r.json())
                .then(d => {
                    document.getElementById('whitelist-ip').value = '';
                    loadWhitelist();
                });
        }
        
        function removeFromWhitelist(ip) {
            fetch('/api/whitelist/' + ip, {method: 'DELETE'})
                .then(r => r.json())
                .then(d => loadWhitelist());
        }
        
        function loadWhitelist() {
            fetch('/api/whitelist')
                .then(r => r.json())
                .then(d => {
                    const html = d.whitelist.map(ip => {
                        return '<div style="padding: 8px; background: rgba(0,255,136,0.1); margin: 5px 0; border-radius: 5px; display: flex; justify-content: space-between;">' +
                            '<span>' + ip + '</span>' +
                            '<button onclick="removeFromWhitelist(\'' + ip + '\')" style="background: rgba(255,107,107,0.1); border-color: #ff6b6b; color: #ff6b6b; padding: 5px 10px; font-size: 11px;">Remove</button>' +
                            '</div>';
                    }).join('');
                    document.getElementById('whitelist-list').innerHTML = html;
                });
        }
        
        function updateConfig() {
            const config = {
                alert_threshold: parseFloat(document.getElementById('alert-threshold').value),
                block_mode: document.getElementById('block-mode-select').value
            };
            
            fetch('/api/config', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(config)
            })
            .then(r => r.json())
            .then(d => alert('Config updated!'));
        }
        
        function loadConfig() {
            fetch('/api/config')
                .then(r => r.json())
                .then(d => {
                    if (d) {
                        const thresholdEl = document.getElementById('alert-threshold');
                        const blockModeEl = document.getElementById('block-mode-select');
                        if (thresholdEl) thresholdEl.value = d.alert_threshold;
                        if (blockModeEl) blockModeEl.value = d.block_mode;
                    }
                })
                .catch(e => console.error('Config load error:', e));
        }
        
        // Инициализация - все функции должны быть определены ПЕРЕД инициализацией
        function initializePage() {
            try {
                loadStatus();
                loadConfig();
                
                // Автоматическая загрузка пакетов при загрузке страницы
                setTimeout(() => {
                    try { loadPackets(); } catch(e) { console.error('loadPackets error:', e); }
                }, 1000);
                
                // Auto-refresh status every 5 seconds
                setInterval(loadStatus, 5000);
                
                // Auto-refresh packets tab every 2 seconds when visible
                setInterval(() => {
                    try {
                        if (document.getElementById('packets').classList.contains('active')) {
                            loadPackets();
                        }
                    } catch(e) { console.error('Packet refresh error:', e); }
                }, 2000);
            } catch(e) {
                console.error('Page initialization error:', e);
            }
        }
        
        // Run initialization when DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initializePage);
        } else {
            initializePage();
        }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Веб-интерфейс управления"""
    return HTML_DASHBOARD