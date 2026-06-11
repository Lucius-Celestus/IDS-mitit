FROM python:3.10-slim

WORKDIR /app

# Установка зависимостей
COPY brain/requirements.txt .
RUN pip install --prefer-binary --no-cache-dir -r requirements.txt

# Копируем всё содержимое папки brain
# После этого файлы окажутся в /app/src/main.py (если структура была такой)
COPY brain/ .

# Копируем proto и генерируем файлы ПРЯМО в папку src/
COPY shared/proto/aegis.proto /tmp/aegis.proto

# Генерируем файлы в ту же папку, где лежет main.py
RUN python -m grpc_tools.protoc -I/tmp --python_out=src --grpc_python_out=src /tmp/aegis.proto

# Create data directories and init model
RUN mkdir -p /app/data/knowledge /app/data/logs

# Create init model script
RUN cat > /tmp/init_model.py << 'INIT_SCRIPT'
import joblib
from sklearn.ensemble import RandomForestClassifier
import numpy as np

model = RandomForestClassifier(n_estimators=10, max_depth=5, random_state=42)
X = np.array([[256, 0.00001, 7.5, 2], [1500, 0.001, 3.2, 1]])
y = np.array([0, 1])
model.fit(X, y)
joblib.dump(model, '/app/data/knowledge/ai1_model.pkl')
print('[+] Model initialized successfully')
INIT_SCRIPT

# Run init script
RUN python /tmp/init_model.py

# Create runtime setup script to regenerate model if corrupted
RUN cat > /tmp/run_brain.sh << 'RUNSCRIPT' && chmod +x /tmp/run_brain.sh
#!/bin/bash
mkdir -p /app/data/knowledge /app/data/logs

# Always recreate model to avoid river dependency
python3 << 'INIT'
import joblib
from sklearn.ensemble import RandomForestClassifier
import numpy as np
try:
    model = joblib.load('/app/data/knowledge/ai1_model.pkl')
    print("[+] Existing model loaded")
except:
    print("[*] Creating new sklearn model...")
    model = RandomForestClassifier(n_estimators=10, max_depth=5, random_state=42)
    X = np.array([[256, 0.00001, 7.5, 2], [1500, 0.001, 3.2, 1]])
    y = np.array([0, 1])
    model.fit(X, y)
    joblib.dump(model, '/app/data/knowledge/ai1_model.pkl')
    print("[+] Model created successfully")
INIT

exec python src/main.py
RUNSCRIPT

# Важно: используем setup скрипт для гарантированной инициализации
ENTRYPOINT ["/tmp/run_brain.sh"]