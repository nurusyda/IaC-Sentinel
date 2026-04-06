FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /home/appuser --shell /usr/sbin/nologin appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY application.py .
COPY index.html .

RUN chown -R appuser:appuser /app

EXPOSE 8080

USER appuser

CMD ["uvicorn", "application:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--log-level", "info"]