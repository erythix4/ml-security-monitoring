# Dockerfile for LLM Attack Simulation Lab
FROM python:3.11-slim

# Metadata
LABEL maintainer="LLM Attack Lab"
LABEL description="Educational Platform for LLM Security Research"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY llm_attack_lab/ ./llm_attack_lab/

# Expose ports
# 8081: Web interface
# 8000: Metrics endpoint
EXPOSE 8081 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/api/status || exit 1

# Default command: Web server mode
CMD ["python", "-m", "llm_attack_lab", "--web"]
