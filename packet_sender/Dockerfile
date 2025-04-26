FROM python:3.10-slim

ENV PYTHONOUNBUFFERED=1

RUN apt get update && \
    apt get install -y --no-install-recommends \
        tcpdump \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sender.py .

EXPOSE 5001

CMD ["python", "sender.py"]