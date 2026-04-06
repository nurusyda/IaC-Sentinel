FROM python:3.12-slim

WORKDIR /app

# System dependencies required by checkov and PyGithub
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY application.py .
COPY index.html .
# Copy static dir if it exists — the COPY won't fail if it's absent
COPY static/ ./static/

# EB reverse proxy (nginx) forwards to port 8080 inside the container
EXPOSE 8080

# Use 2 workers — enough for EB's single-instance t3.small default
CMD ["uvicorn", "application:app", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--workers", "2", \
     "--log-level", "info"]