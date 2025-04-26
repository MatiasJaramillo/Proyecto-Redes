# sender_api.py
from flask import Flask, jsonify
import random, time
from threading import Thread
from scapy.all import send, IP, TCP

app = Flask(__name__)

def do_send(flags: str):
    pkt = IP(dst="packet_sniffer")/TCP(
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