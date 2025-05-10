#!/usr/bin/env python3

import logging
import json
import time
import random
import os
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List
from dataclasses import dataclass

import docker
import requests
from prometheus_client import Counter, Histogram, Gauge, start_http_server

# === Configuration Constants ===

STATE_FILE        = "/home/student/dcd-unified/state/attacker_state.json"
ELK_QUEUE_FILE    = "/home/student/dcd-unified/state/elk_retry_queue.json"
FETCH_WINDOW_SEC  = 60     # look-back window for new events
COOLDOWN_SEC      = 300    # how long to wait before scaling down

# Start Prometheus metrics server
start_http_server(8001)

# Prometheus metrics
RESPONSES_EXECUTED   = Counter('responses_executed_total',   'Total dynamic responses executed')
RESPONSES_SUCCESSFUL = Counter('responses_successful_total', 'Successful dynamic responses')
RESPONSE_LATENCY     = Histogram('response_latency_seconds',  'Response latency')
ACTIVE_HONEYPOTS     = Gauge('active_honeypots',             'Number of honeypots currently scaled up')
LAST_SCALE_TIME      = Gauge('last_scale_timestamp',        'Unix timestamp of last scale event per service',
                             ['service'])

logger = logging.getLogger("dynamic_response")
logging.basicConfig(level=logging.INFO)

@dataclass
class Honeypot:
    name: str
    service: str
    bias: str

HONEYPOTS: List[Honeypot] = [
    Honeypot("cowrie",     "cowrie_cowrie",    "anchoring"),
    Honeypot("dionaea",    "dionaea_dionaea",  "confirmation"),
    Honeypot("elasticpot", "elasticpot_honeypot_elasticpot_triggered", "overconfidence"),
    Honeypot("heralding",  "honeypot_heralding_triggered",           "overconfidence"),
    Honeypot("tanner",     "honeypot_tanner_triggered",              "anchoring"),
]

class DynamicResponseManager:
    def __init__(self, es_host="localhost", es_port=9200):
        self.docker      = docker.from_env()
        self.es_url      = f"http://{es_host}:{es_port}/dynamic-responses/_doc"
        self.state       = self._load_state()
        self.last_scaled: Dict[str, datetime] = {}
        logger.info("DynamicResponseManager initialized")

    # ─── State persistence ─────────────────────────────────────
    def _load_state(self) -> Dict[str, Any]:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE) as f:
                return json.load(f)
        return {}

    def _save_state(self):
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(self.state, f, indent=2)

    # ─── Event ingestion ───────────────────────────────────────
    def fetch_recent_events(self) -> List[Dict[str, Any]]:
        cutoff = datetime.utcnow() - timedelta(seconds=FETCH_WINDOW_SEC)
        events: List[Dict[str, Any]] = []
        for hp in HONEYPOTS:
            log_path = f"/home/student/dcd-unified/data/{hp.name}/log/{hp.name}.json"
            if not os.path.exists(log_path):
                continue
            with open(log_path) as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                        ts = datetime.fromisoformat(rec.get("timestamp", rec.get("time")))
                        if ts < cutoff:
                            continue
                        if any(k in line for k in ("login attempt","scan","exploit")):
                            ip = rec.get("src_ip") or rec.get("remote_host")
                            events.append({"ip": ip, "bias": hp.bias, "when": ts})
                    except Exception:
                        continue
        return events

    def active_attackers(self) -> Dict[str, List[datetime]]:
        mapping: Dict[str, List[datetime]] = {}
        for e in self.fetch_recent_events():
            mapping.setdefault(e["ip"], []).append(e["when"])
        return mapping

    # ─── Scaling logic ─────────────────────────────────────────
    def trigger_honeypot(self, bias: str, attacker_ip: str):
        candidates = [h for h in HONEYPOTS if h.bias == bias]
        if not candidates:
            return
        hp = random.choice(candidates)
        svc = self.docker.services.get(hp.service)
        curr = svc.attrs['Spec']['Mode']['Replicated']['Replicas']
        svc.scale(curr + 1)
        now = datetime.utcnow()
        self.last_scaled[hp.service] = now
        LAST_SCALE_TIME.labels(service=hp.service).set(now.timestamp())
        ACTIVE_HONEYPOTS.set(len(self.last_scaled))
        logger.info(f"Scaled UP {hp.service} → {curr+1}")

    def should_scale_down(self, svc_name: str) -> bool:
        last = self.last_scaled.get(svc_name)
        if not last: return False
        if (datetime.utcnow() - last).seconds < COOLDOWN_SEC:
            return False
        return len(self.active_attackers()) == 0

    def scale_down_honeypots(self):
        for svc, last in list(self.last_scaled.items()):
            if self.should_scale_down(svc):
                service = self.docker.services.get(svc)
                curr = service.attrs['Spec']['Mode']['Replicated']['Replicas']
                if curr > 1:
                    service.scale(curr - 1)
                    logger.info(f"Scaled DOWN {svc} → {curr-1}")
                del self.last_scaled[svc]
        ACTIVE_HONEYPOTS.set(len(self.last_scaled))

    # ─── Elasticsearch logging ─────────────────────────────────
    def log_to_elasticsearch(self, ip: str, bias: str, rtype: str):
        doc = {
            "@timestamp": datetime.utcnow().isoformat(),
            "attacker_ip": ip,
            "response.bias": bias,
            "response.type": rtype
        }
        try:
            r = requests.post(self.es_url, json=doc, timeout=3)
            r.raise_for_status()
        except Exception:
            with open(ELK_QUEUE_FILE, "a") as f:
                f.write(json.dumps(doc) + "\n")
            logger.warning("Buffered ES doc, will retry later")

    def replay_elk_queue(self):
        if not os.path.exists(ELK_QUEUE_FILE):
            return
        lines = open(ELK_QUEUE_FILE).read().splitlines()
        kept = []
        for ln in lines:
            doc = json.loads(ln)
            try:
                r = requests.post(self.es_url, json=doc, timeout=3)
                r.raise_for_status()
            except:
                kept.append(ln)
        with open(ELK_QUEUE_FILE, "w") as f:
            f.write("\n".join(kept))

    # ─── Apply response ────────────────────────────────────────
    def apply_response(self, bias: str, attacker_ip: str) -> bool:
        # identical to your original, but fix decoy-file path:
        templates = {
            "anchoring": [
                {"type":"misleading_info","message":"System vuln to CVE-2021-41773"},
                {"type":"fake_error","error":"Access Denied","hint":"Try admin:admin"}
            ],
            "confirmation": [
                {"type":"decoy_file","filename":"credentials.txt","content":"admin:password123"},
                {"type":"delayed_response","delay":5}
            ],
            "overconfidence": [
                {"type":"fake_success","message":"Access granted to /root","content":"Sensitive data found."},
                {"type":"challenge","hint":"Bypass required for internal auth"}
            ]
        }
        resp = random.choice(templates.get(bias, []))
        rtype = resp["type"]
        logger.info(f"Applying {rtype} for {bias}")
        try:
            if rtype == "decoy_file":
                # ensure bait folder exists
                bait_dir = f"/home/student/dcd-unified/data/{bias}/bait"
                os.makedirs(bait_dir, exist_ok=True)
                path = os.path.join(bait_dir, resp["filename"])
                with open(path, "w") as f:
                    f.write(resp["content"])
            elif rtype == "delayed_response":
                time.sleep(resp["delay"])
            elif rtype == "misleading_info":
                logger.info(f"[Deception] {resp['message']}")
            elif rtype == "fake_error":
                logger.info(f"[Fake Error] {resp['error']} — {resp['hint']}")
            elif rtype == "fake_success":
                logger.info(f"[Fake Success] {resp['message']} → {resp['content']}")
            elif rtype == "challenge":
                logger.info(f"[Challenge] {resp['hint']}")
            self.log_to_elasticsearch(attacker_ip, bias, rtype)
            RESPONSES_EXECUTED.inc()
            RESPONSES_SUCCESSFUL.inc()
            return True
        except Exception as e:
            logger.error(f"Error applying response: {e}")
            return False

# ─── Main loop when run standalone ─────────────────────────
if __name__ == "__main__":
    mgr = DynamicResponseManager()
    while True:
        # scale-up on real events
        for evt in mgr.fetch_recent_events():
            mgr.trigger_honeypot(evt["bias"], evt["ip"])
        # then scale-down if idle
        mgr.scale_down_honeypots()
        # flush ELK buffer
        mgr.replay_elk_queue()
        time.sleep(FETCH_WINDOW_SEC)

