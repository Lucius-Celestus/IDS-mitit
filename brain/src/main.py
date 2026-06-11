import grpc
from concurrent import futures
import time
import os
import json
import joblib
from datetime import datetime

# Импортируем сгенерированные файлы (они будут лежать в той же папке src)
try:
    import aegis_pb2
    import aegis_pb2_grpc
    from learning import IntelligentHeuristics
except ImportError:
    from . import aegis_pb2
    from . import aegis_pb2_grpc
    from .learning import IntelligentHeuristics

class AegisService(aegis_pb2_grpc.AegisServiceServicer):
    def __init__(self, model_path):
        self.model_path = model_path
        self.model = self._load_model()
        
        # Инициализируем интеллектуальную систему эвристик
        self.heuristics = IntelligentHeuristics(self.model)
        
        os.makedirs("/app/data/logs", exist_ok=True)
        print(f"[*] Инициализация AegisService завершена. Путь к логам: /app/data/logs")
        print(f"[+] Загружена система интеллектуальных эвристик")

    def _load_model(self):
        if os.path.exists(self.model_path):
            print(f"[+] Загрузка AI-модели из {self.model_path}")
            return joblib.load(self.model_path)
        print("[!] ВНИМАНИЕ: Модель не найдена. Работа в режиме эвристик без ИИ.")
        return None

    def Analyze(self, request, context):
        """Анализ пакета с детальным логированием процесса"""
        
        # Подготовка признаков для анализа
        features = {
            'packet_len': float(request.packet_len),
            'iat': float(request.iat),
            'entropy': float(request.entropy),
            'tcp_flags': int(request.tcp_flags),
        }
        
        # Анализируем через интеллектуальную систему
        confidence, formula = self.heuristics.analyze_with_ai(features)
        self.heuristics.update_history(confidence)
        
        # Логируем детальную формулу расчета
        print(
            f"[*] Brain[{request.src_ip}]: {formula}",
            flush=True
        )

        # Динамический порог: 0.75 для нормальных, 0.85 для подозрительных
        is_attack = confidence > 0.75
        
        if is_attack:
            alert = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": request.src_ip,
                "confidence": confidence,
                "features": features,
                "analysis": formula,
                "type": "MALICIOUS_TRAFFIC"
            }
            # Запись в файл для Ока (Eye)
            with open("/app/data/logs/alerts.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(alert) + "\n")
                f.flush()
                print(f"[ALERT] 🚨 Запись атаки в лог: {request.src_ip} (conf={confidence:.3f})", flush=True)
        else:
            # Логируем безопасные пакеты (можно отключить в production)
            if confidence > 0.50:
                print(f"[WARN] ⚠️  Подозрительный пакет от {request.src_ip} (conf={confidence:.3f})", flush=True)

        return aegis_pb2.Verdict(
            target_ip=request.src_ip,
            drop=bool(is_attack),
            confidence=float(confidence)
        )

def serve():
    print("[*] Подготовка gRPC сервера...")
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    aegis_pb2_grpc.add_AegisServiceServicer_to_server(
        AegisService("/app/data/knowledge/ai1_model.pkl"), server
    )
    
    server.add_insecure_port('0.0.0.0:50051')
    server.start()
    print("[+] Aegis-Brain успешно запущен на порту 50051")
    
    # ЭТОТ ВЫЗОВ НЕ ДАЕТ СКРИПТУ ЗАВЕРШИТЬСЯ
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        print("[!] Остановка сервера...")
        server.stop(0)

if __name__ == "__main__":
    print("[*] Точка входа main.py активирована.")
    serve()