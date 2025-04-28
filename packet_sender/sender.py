# sender.py
import os
import random, time
from threading import Thread
from flask import Flask, jsonify
from scapy.all import send, IP, TCP

app = Flask(__name__)

# Interceptor’s address on red-a; can override via Docker ENV INTERCEPT_HOST
INTERCEPT_HOST = os.getenv("INTERCEPT_HOST", "172.18.1.3")

def do_send(flags: str):
    pkt = IP(dst=INTERCEPT_HOST)/TCP(
        sport = random.randint(1025, 65535),
        dport = 80,
        flags = flags
    )
    send(pkt, verbose=False)
    return pkt.summary()

@app.route("/send_fpu", methods=["POST"])
def send_fpu():
    summary = do_send("FPU")   # FIN+PSH+URG
    return jsonify({"sent": summary})

@app.route("/send_null", methods=["POST"])
def send_null():
    summary = do_send("")      # no flags
    return jsonify({"sent": summary})

def auto_loop():
    """Send a normal PSH+ACK packet every second."""
    while True:
        do_send("PA")
        time.sleep(1)

if __name__ == "__main__":
    Thread(target=auto_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=5001)
