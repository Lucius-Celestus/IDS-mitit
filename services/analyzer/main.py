import os
import time
import pandas as pd
import lightgbm as lgb
import logging
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
from core.mitigator import RawMitigator

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# Конфигурация
MODEL_PATH = os.environ.get("MODEL_PATH")
INFLUX_URL = "http://localhost:8086"
TOKEN = os.environ.get("INFLUX_TOKEN")
ORG = os.environ.get("INFLUX_ORG")
BUCKET = os.environ.get("INFLUX_BUCKET")
THRESHOLD = float(os.environ.get("PROB_THRESHOLD", 0.85))

# Инициализация сервисов
client = InfluxDBClient(url=INFLUX_URL, token=TOKEN, org=ORG)
query_api = client.query_api()
write_api = client.write_api(write_options=SYNCHRONOUS)
mitigator = RawMitigator(os.environ.get("WHITELIST", "127.0.0.1"))

def classify_threat(row):
    spkts, dpkts = row.get('spkts', 0), row.get('dpkts', 0)
    # Если исходящих много, а входящих почти нет - это агрессор
    if spkts > 100 and dpkts < 10:
        return "SYN Flood / DoS"
    # Если много в обе стороны - это жертва (Backscatter)
    if spkts > 100 and dpkts > 100:
        return "Server_Response_Ignore"
    return "Anomaly"

logging.info("ids Analyzer loading LightGBM model...")
bst = lgb.Booster(model_file=MODEL_PATH)

while True:
    try:
        query = f'from(bucket: "{BUCKET}") |> range(start: -1m) |> filter(fn: (r) => r["_measurement"] == "network_flow") |> pivot(rowKey:["_time", "src_ip", "dst_ip"], columnKey: ["_field"], valueColumn: "_value")'
        result = query_api.query_data_frame(query)

        if result is not None and not result.empty:
            df = pd.concat(result) if isinstance(result, list) else result
            features = ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'sttl', 'dttl']
            for col in features:
                if col not in df.columns: df[col] = 0
            
            X = df[features].astype(float)
            preds = bst.predict(X)

            for i, prob in enumerate(preds):
                if prob > THRESHOLD:
                    src = df['src_ip'].iloc[i]
                    threat = classify_threat(df.iloc[i])
                    
                    if "Ignore" not in threat:
                        logging.warning(f"THREAT DETECTED: {threat} from {src} (Prob: {prob:.2f})")
                        if mitigator.block(src):
                            # Логируем алерт обратно в Influx для Grafana
                            point = Point("ids_alert").tag("src_ip", src).tag("type", threat).field("conf", prob)
                            write_api.write(bucket=BUCKET, record=point)
        
        time.sleep(5)
    except Exception as e:
        logging.error(f"Main loop error: {e}")
        time.sleep(5)