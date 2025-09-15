FROM python:3.9-slim

# 1) Install Suricata
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y suricata && \
    rm -rf /var/lib/apt/lists/*

# 2) Copy your Suricata config
COPY suricata.yaml /etc/suricata/suricata.yaml

# 3) Copy your tail-wrapper
COPY signature_detector.py /app/signature_detector.py
WORKDIR /app
RUN chmod +x signature_detector.py

# 4) Ensure log directory exists
RUN mkdir -p /var/log/suricata

# 5) Start Suricata + tail wrapper
CMD ["./signature_detector.py"]

