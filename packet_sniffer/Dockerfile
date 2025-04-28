FROM python:3.10-slim

ENV PYTHONOUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tcpdump \
        iproute2 && \
      rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sniffer.py .

EXPOSE 5000

CMD ["python", "sniffer.py"]

