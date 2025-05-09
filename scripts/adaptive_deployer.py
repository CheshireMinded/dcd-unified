#!/usr/bin/env python3
"""
Adaptive Deployer 2.0  

One script to rule them all: log‑watching, dynamic honeypot scaling,
cognitive‑bias responses, Prometheus metrics, and ES logging.

"""

# ── stdlib ─────────────────────────────────────────────────────────────
import os, json, time, random, logging, hashlib, signal, sys, traceback
from datetime import datetime
from typing import Dict, Any, List
from dataclasses import dataclass

# ── 3rd‑party ──────────────────────────────────────────────────────────
try:
    import docker, requests
    from prometheus_client import (
        Counter, Histogram, Gauge, start_http_server
    )
except ImportError as e:
    print("Missing deps; run: pip install docker requests prometheus_client")
    sys.exit(1)

# ── constants / paths ─────────────────────────────────────────────────
STATE_FILE     = "/home/student/dcd-unified/state/attacker_state.json"
ELK_QUEUE_FILE = "/home/student/dcd-unified/state/elk_retry_queue.jsonl"
METRICS_PORT   = 8000   # Prom‑scraping

LOG_PATHS = {
    # bias           log‑file
    "anchoring"     : "/home/student/dcd-unified/data/cowrie/logs/cowrie.json",
    "confirmation"  : "/home/student/dcd-unified/data/dionaea/logs/dionaea.json",
    "overconfidence": "/home/student/dcd-unified/data/elasticpot/logs/elasticpot.json",
}

HONEYPOTS = [
    {"service": "cowrie",     "bias": "anchoring"},
    {"service": "dionaea",    "bias": "confirmation"},
    {"service": "elasticpot", "bias": "overconfidence"},
    {"service": "heralding",  "bias": "overconfidence"},
    {"service": "tanner",     "bias": "anchoring"},
]

# ── logging setup ─────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s %(levelname)s  %(message)s",
    level=logging.INFO
)
log = logging.getLogger("adaptive_deployer")

# ── Prometheus metrics ────────────────────────────────────────────────
RESPONSES_EXECUTED   = Counter('responses_executed_total',   'All responses run')
RESPONSES_SUCCESSFUL = Counter('responses_successful_total', 'Responses OK')
RESPONSE_LATENCY     = Histogram('response_latency_seconds', 'Response latency')
ACTIVE_RESPONSES     = Gauge('active_responses', 'Responses currently poppin’')
RESPONSE_HEALTH      = Gauge('response_health', '1=OK,0=bad', ['response_type'])

# ── dynamic response engine ───────────────────────────────────────────
@dataclass
class DynamicResponse:
    type: str; bias: str; attacker_ip: str
    timestamp: float; parameters: Dict[str, Any]

class DynamicResponseManager:
    def __init__(self, es="http://localhost:9200"):
        self.docker = docker.from_env()
        self.es_url = es
        self.templates = self._load_templates()
        self.state = self._load_json(STATE_FILE, default={})
        log.info("DynamicResponseManager ready to yeet ")

    # ——— template goodies ————————————————————————————————
    def _load_templates(self):
        return {
            "anchoring": [
                {"type": "misleading_info", "message": "System vuln to CVE‑2021‑41773"},
                {"type": "fake_error", "error": "Access Denied", "hint": "try admin:admin"},
            ],
            "confirmation": [
                {"type": "decoy_file", "filename": "credentials.txt", "content": "admin:password123"},
                {"type": "delayed_response", "delay": 5},
            ],
            "overconfidence": [
                {"type": "fake_success", "message": "Access granted to /root", "content": "sensitive data.txt"},
                {"type": "challenge", "hint": "bypass required "},
            ],
        }

    # ——— persistence helpers ————————————————————————————
    @staticmethod
    def _load_json(path, default):
        try:
            with open(path) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return default

    def _save_state(self):
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(self.state, f, indent=2)

    # ——— attacker profile sauce ——————————————————————————
    def _codename(self, ip, bias):
        h = int(hashlib.sha256(ip.encode()).hexdigest(), 16) % 10000
        fam = {"anchoring":"Storm","confirmation":"Tempest","overconfidence":"Typhoon"}.get(bias,"Storm")
        return f"{fam}-{h:04d}"

    def _update_profile(self, ip, bias, rtype):
        p = self.state.get(ip, {
            "session_count":0, "bias_history":[], "response_history":[],
            "frustration":0.0, "confidence":0.0
        })
        p.setdefault("profile_name", self._codename(ip,bias))
        p["session_count"] += 1
        p["bias_history"].append(bias)
        p["response_history"].append(rtype)
        if rtype in ("fake_error","challenge"):
            p["frustration"] += 0.1
        if rtype == "fake_success":
            p["confidence"] += 0.2
        p["last_seen"] = datetime.utcnow().isoformat()
        self.state[ip] = p
        self._save_state()

    # ——— docker scaling ————————————————————————————————
    def trigger_honeypot(self, bias):
        hp = random.choice([h for h in HONEYPOTS if h["bias"] == bias] or [{}])
        svc_name = hp.get("service")
        if not svc_name:
            log.warning(f"No honeypot mapped to bias '{bias}'")
            return
        try:
            svc = self.docker.services.get(svc_name)
            repl = svc.attrs['Spec']['Mode']['Replicated']['Replicas']
            svc.scale(repl + 1)
            log.info(f"Scaled {svc_name} {repl} → {repl+1}")
        except docker.errors.NotFound:
            log.error(f"Service {svc_name} not found (did you deploy stack?)")
        except Exception:
            log.exception(f"Failed to scale {svc_name}")

    # ——— response dispatcher —————————————————————————————
    @RESPONSE_LATENCY.time()
    def apply_response(self, bias, ip):
        tmpl = random.choice(self.templates.get(bias, []) or [{}])
        rtype = tmpl.get("type", "noop")
        ACTIVE_RESPONSES.inc()
        try:
            if rtype == "decoy_file":
                path = f"/home/student/dcd-unified/data/cowrie/bait/{tmpl['filename']}"
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f: f.write(tmpl["content"])
            elif rtype == "delayed_response":
                time.sleep(tmpl["delay"])
            elif rtype == "misleading_info":
                log.info(f" {tmpl['message']}")
            elif rtype == "fake_error":
                log.info(f" {tmpl['error']} — {tmpl['hint']}")
            elif rtype == "fake_success":
                log.info(f" {tmpl['message']} → {tmpl['content']}")
            elif rtype == "challenge":
                log.info(f" Challenge: {tmpl['hint']}")
            else:
                log.debug("noop, chillin’ ")

            self._update_profile(ip, bias, rtype)
            self._log_es(ip, bias, rtype)
            RESPONSES_EXECUTED.inc(); RESPONSES_SUCCESSFUL.inc()
            RESPONSE_HEALTH.labels(rtype).set(1)
        except Exception:
            # big yikes, but we catch all so the loop keeps vibing
            log.exception("apply_response blew up")
            RESPONSE_HEALTH.labels(rtype).set(0)
        finally:
            ACTIVE_RESPONSES.dec()

    # ——— ES logging w/ retry queue ————————————————————————
    def _log_es(self, ip, bias, rtype):
        doc = {
            "@timestamp": datetime.utcnow().isoformat(),
            "attacker_ip": ip,
            "response": {"bias": bias, "type": rtype},
            "attacker": self.state.get(ip,{}).get("profile_name","unknown"),
        }
        try:
            requests.post(f"{self.es_url}/dynamic-responses/_doc",
                          json=doc, timeout=3).raise_for_status()
        except Exception as e:
            log.debug(f"ES down, queueing doc ({e})")
            os.makedirs(os.path.dirname(ELK_QUEUE_FILE), exist_ok=True)
            with open(ELK_QUEUE_FILE,"a") as f: f.write(json.dumps(doc)+"\n")

    def flush_queue(self):
        if not os.path.isfile(ELK_QUEUE_FILE):
            return
        lines = open(ELK_QUEUE_FILE).readlines()
        if not lines: return
        ok = []
        for l in lines:
            try:
                requests.post(f"{self.es_url}/dynamic-responses/_doc",
                              json=json.loads(l), timeout=3).raise_for_status()
                ok.append(l)
            except Exception:
                break
        if ok:
            with open(ELK_QUEUE_FILE,"w") as f:
                for l in lines:
                    if l not in ok: f.write(l)
            log.info(f"Flushed {len(ok)} queued docs → ES")

# ── util helpers ───────────────────────────────────────────────────────
def wait_for_services():
    log.info("Waiting for Docker & ES (brb)…")
    client = docker.from_env()
    while True:
        try:
            client.ping()
            requests.get("http://localhost:9200", timeout=2)
            break
        except Exception:
            time.sleep(3)
    log.info("All services online. Let’s groove ✨")

def extract_ip(line:str) -> str:
    try:
        data = json.loads(line)
        return data.get("src_ip") or data.get("remote_host") or "0.0.0.0"
    except Exception:
        return "0.0.0.0"

# ── graceful shutdown (because Ctrl‑C happens) ─────────────────────────
stop_flag = False
def _bye(signum, frame):
    global stop_flag
    stop_flag = True
    log.warning("Shutdown requested ‑ wrapping up…")

for s in (signal.SIGINT, signal.SIGTERM):
    signal.signal(s, _bye)

# ── main monitor loop ──────────────────────────────────────────────────
def monitor(mgr: DynamicResponseManager):
    positions = {p:0 for p in LOG_PATHS.values()}
    tick = 0
    while not stop_flag:
        try:
            for bias, path in LOG_PATHS.items():
                if not os.path.isfile(path):
                    continue
                with open(path) as f:
                    f.seek(positions[path])
                    for line in f:
                        if not line.strip(): continue
                        if any(w in line for w in ("login attempt","scan","exploit")):
                            ip = extract_ip(line)
                            log.info(f" Trigger {bias} bias from {ip}")
                            mgr.trigger_honeypot(bias)
                            mgr.apply_response(bias, ip)
                    positions[path] = f.tell()
            tick += 1
            if tick % 60 == 0:
                mgr.flush_queue()
        except Exception:
            log.error("Uncaught error—stacktrace incoming:")
            traceback.print_exc()
        time.sleep(1)
    log.info("Monitor loop exited. Later bruh")

# ── entrypoint ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        start_http_server(METRICS_PORT)
        log.info(f"Prometheus metrics on :{METRICS_PORT}")
    except Exception:
        log.error("Could not start Prometheus endpoint (but continuing)…")
    wait_for_services()
    monitor(DynamicResponseManager())
