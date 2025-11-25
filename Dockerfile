FROM python:3.11-slim

# System-Pakete (ping)
RUN apt-get update && \
    apt-get install -y --no-install-recommends iputils-ping && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python-Abhängigkeiten
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App-Code & Config
COPY uptime_monitor.py ./
COPY known_hosts.txt ./known_hosts.txt

# Port, auf dem Flask läuft
EXPOSE 8000

# Standard-Command
CMD ["python", "uptime_monitor.py"]
