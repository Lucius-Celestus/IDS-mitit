FROM python:3.11-slim

# Установка системных зависимостей для работы с сетью
RUN apt-get update && apt-get install -is \
    iptables \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
CMD ["python", "main.py"]