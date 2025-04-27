# syntax=docker/dockerfile:1.4

FROM giantituana/snort-in-the-middle:1.0
USER root

# install python, build tools, NFQUEUE headers, & iptables
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip \
        build-essential python3-dev \
        libnetfilter-queue-dev \
        tcpdump iptables && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY interceptor.py .

EXPOSE 5002

# start inline Snort + our Flask API
CMD bash -lc "\
    sysctl -w net.ipv4.ip_forward=1 && \
    iptables -I FORWARD -j NFQUEUE --queue-num 1 && \
    snort -Q --daq nfq --daq-var queue=1 -q \
          -i eth0 -c /etc/snort/snort.conf -l /var/log/snort/alerts & \
    python3 interceptor.py\
"


