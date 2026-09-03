FROM python:3.11-slim

# Install Nmap and required system packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        iproute2 \
        net-tools \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Application directory
WORKDIR /app

# Install Python dependencies first
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Render provides the PORT environment variable
ENV PYTHONUNBUFFERED=1

EXPOSE 10000

# IMPORTANT:
# Change app:app if your Flask object has a different location/name.
CMD ["sh", "-c", "python -m flask --app app run --host=0.0.0.0 --port=${PORT:-10000}"]