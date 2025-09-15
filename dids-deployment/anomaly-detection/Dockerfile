FROM python:3.9-slim

WORKDIR /app

# Copy all necessary files
COPY . .

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Set the entrypoint
CMD ["python", "anomaly_detector.py"]

