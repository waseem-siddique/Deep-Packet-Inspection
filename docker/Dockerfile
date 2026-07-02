FROM python:3.11-slim

LABEL maintainer="Mohammed Waseem Siddique"
LABEL description="Deep Packet Inspection Engine"

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN pip install --no-cache-dir -e .

EXPOSE 5000 8000

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]