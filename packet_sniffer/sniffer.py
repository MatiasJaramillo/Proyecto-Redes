# sniffer_api.py
from flask import Flask, jsonify import threading
from scapy.all import sniff, TCP
import datetime
app = Flask (__name__)
logs=0
_sniffing = threading.Event ()
def detect_scan(pkt) :
if not pkt.haslayer (TCP) :
return None
flags = pkt (TCP].flags
# Xmas tree = FIN(0x01)+PSH(0x08)+URG(0x20) exactly
if flags & 1 and flags & 8 and flags & 32 and flags
return
"FPU"
# Null scan = no flags
if flags == 0:
return "NULL"
return None
• ~ (1|8|32)
== 0:
def _sniff_loop():
def handler (pkt) :
ts = datetime.datetime.now().isoformat()
stype = detect_scan(pkt)
entry = $
"timestamp": ts,
"summary": pkt.summary(),
"scan_type": stype,
"suspicious": stype is not None
logs. append (entry) if len(logs) > 100:
logs.pop (0)
while
_sniffing. is_set ():
# timeout so we can check the Event flag regularly
sniff(filter="ip"
', prnshandler, store=0, timeout=1, iface="ethe")
@app.route("/stant_sniff"
', methods= ["POST"] )
def start_sniff():
if not
_sniffing. is_set:
_sniffing.seto
threading. Thread (target=_sniff_loop,
daemon=True) .start()
return jsonify({"status": "sniffing started"})

@app.route("/stop_sniff"', methods= ["POST"])
def stop_sniff():
_sniffing.clear (
return jsonify({"status": "sniffing stopped"})
@app.route("/logs", methods= ["GET"] )
def get_logs() :
return jsonify(logs)
if __name_
__main_
":
# don't auto-start sniffing; wait for GuI
app.run(host="0.0.0.0", port=5000)
