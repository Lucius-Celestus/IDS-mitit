FROM python:3.10-slim-bookworm

WORKDIR /app

# Устанавливаем зависимости
COPY eye/requirements.txt .
COPY brain/requirements.txt brain_reqs.txt
RUN pip install --no-cache-dir --prefer-binary -r requirements.txt -r brain_reqs.txt

# Копируем проект (помним, что контекст сборки — корень проекта)
COPY eye /app/eye
COPY brain/src /app/src
COPY shared /app/shared

# Генерируем gRPC код внутри контейнера
RUN python -m grpc_tools.protoc -I/app/shared/proto \
    --python_out=/app/eye/api \
    --grpc_python_out=/app/eye/api \
    /app/shared/proto/aegis.proto

# Переходим в рабочую папку API
WORKDIR /app/eye/api

# Запуск
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]