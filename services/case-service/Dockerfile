FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt ./
RUN pip install --upgrade pip && pip wheel --wheel-dir=/wheels -r requirements.txt

FROM python:3.12-slim
WORKDIR /app
RUN useradd -m appuser && mkdir -p /home/appuser/data/case-evidence \
    && chown -R appuser:appuser /home/appuser/data
COPY --from=builder /wheels /wheels
RUN pip install --no-cache /wheels/*
COPY app ./app
USER appuser
EXPOSE 8001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
