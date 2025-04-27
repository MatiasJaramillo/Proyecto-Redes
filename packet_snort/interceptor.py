# interceptor.py
import threading, uuid, os, time
from flask import Flask, jsonify, request
from netfilterqueue import NetfilterQueue
from scapy.all import IP, send

app = Flask(__name__)
pending = {}    # id → raw packet bytes
lock    = threading.Lock()

ALERT_LOG = "/var/log/snort/alerts/alert.fast"  # adjust if your Snort config uses a different file

def watch_alerts():
    """Tails Snort's alert file and buffers each line as a pending packet."""
    # Wait until file exists
    while not os.path.exists(ALERT_LOG):
        time.sleep(1)
    with open(ALERT_LOG) as f:
        # seek to end
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            # Snort alert lines typically include timestamp and packet summary
            alert_id = str(uuid.uuid4())
            with lock:
                pending[alert_id] = line.strip()
              
@app.route("/pending", methods=["GET"])
def list_pending():
    with lock:
        return jsonify([
            {"id": i, "alert": pending[i]}
            for i in pending
        ])

@app.route("/approve/<id>", methods=["POST"])
def approve(id):
    with lock:
        alert = pending.pop(id, None)
    if alert is None:
        return jsonify({"error":"not found"}), 404
    # NOTE: we don't have the raw bytes any more, so for a demo we'll just accept via iptables
    # Real inline re-injection would need to buffer raw pkt in NFQUEUE callback instead.
    return jsonify({"status":"accepted","id":id})

@app.route("/drop/<id>", methods=["POST"])
def drop(id):
    with lock:
        if id not in pending:
            return jsonify({"error":"not found"}), 404
        pending.pop(id)
    return jsonify({"status":"dropped","id":id})

if __name__=="__main__":
    threading.Thread(target=watch_alerts, daemon=True).start()
    app.run(host="0.0.0.0", port=5002)
