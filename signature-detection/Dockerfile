FROM python:3.9-slim
WORKDIR /app
COPY . .
RUN apt update && apt install -y suricata
COPY suricata.yaml /etc/suricata/suricata.yaml
CMD ["suricata", "-c", "/etc/suricata/suricata.yaml", "-i", "eth0"]
