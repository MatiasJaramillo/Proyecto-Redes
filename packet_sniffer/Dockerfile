# Use an official lightweight Python runtime
From python:3.10-slim
# Prevent Python from buffering stdout/stderr (so logs appear immediately)
ENV PYTHONUNBUFFERED=1
# Install OS-level deps scapy may need
RUN apt-get update 8&\
apt-get install -y --no-install-recommends \
codump
8 rm -rf /var/lib/apt/Lists/*
# Copy in your requirements and install them
WORKDIR /app
COPY requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
# Copy your sniffer code
COPY sniffer.py
# Give Docker the capability to sniff traffic
# (you'll still need --privileged or CAP_NET_RAN at runtime)
# Expose the port
EXPOSE 5000
# Default command
CMD ["python", "sniffer.py"]
