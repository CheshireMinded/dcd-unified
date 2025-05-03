#!/usr/bin/env python3

import logging
import json
import time
import random
import os
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

import docker
import requests
from prometheus_client import Counter, Histogram, Gauge, Summary

# Constants
STATE_FILE = "/home/student/dcd-unified/state/attacker_state.json"
ELK_QUEUE_FILE = "/home/student/dcd-unified/state/elk_retry_queue.jsonl"

HONEYPOTS = [
    {"name": "cowrie", "service": "cowrie", "bias": "anchoring"},
    {"name": "dionaea", "service": "dionaea", "bias": "confirmation"},
    {"name": "elasticpot", "service": "elasticpot", "bias": "overconfidence"}
]

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dynamic_response")

# Prometheus metrics
RESPONSES_EXECUTED = Counter('responses_executed', 'Total dynamic responses executed')
RESPONSES_SUCCESSFUL = Counter('responses_successful', 'Successful dynamic responses')
RESPONSE_LATENCY = Histogram('response_latency_seconds', 'Response latency')
ACTIVE_RESPONSES = Gauge('active_responses', 'Active cognitive responses')
RESPONSE_HEALTH_STATUS = Gauge('response_health', 'Response health by type', ['response_type'])

@dataclass
class DynamicResponse:
    type: str
    bias: str
    attacker_ip: str
    timestamp: float
    parameters: Dict[str, Any]

class DynamicResponseManager:
    def __init__(self, es_host: str = "localhost", es_port: int = 9200):
        self.docker_client = docker.from_env()
        self.es_url = f"http://{es_host}:{es_port}"
        self.response_templates = self._load_response_templates()
        self.attacker_state = self._load_attacker_state()
        logger.info("DynamicResponseManager initialized")

    def _load_response_templates(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "anchoring": [
                {"type": "misleading_info", "message": "System vulnerable to CVE-2021-41773"},
                {"type": "fake_error", "error": "Access Denied", "hint": "Try admin:admin"}
            ],
            "confirmation": [
                {"type": "decoy_file", "filename": "credentials.txt", "content": "admin:password123"},
                {"type": "delayed_response", "delay": 5}
            ],
            "overconfidence": [
                {"type": "fake_success", "message": "Access granted to /root", "content": "Sensitive data found."},
                {"type": "challenge", "hint": "Bypass required for internal auth"}
            ]
        }

    def _load_attacker_state(self) -> Dict[str, Any]:
        if not os.path.exists(STATE_FILE):
            return {}
        with open(STATE_FILE, "r") as f:
            return json.load(f)

    def _save_attacker_state(self):
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(self.attacker_state, f, indent=2)

    def _generate_attacker_codename(self, ip: str, bias: str) -> str:
        h = int(hashlib.sha256(ip.encode()).hexdigest(), 16) % 10000
        family = {
            "anchoring": "Storm",
            "confirmation": "Tempest",
            "overconfidence": "Typhoon"
        }.get(bias, "Storm")
        return f"{family}-{h:04d}"

    def _update_attacker_profile(self, attacker_ip: str, bias: str, response_type: str):
        now = datetime.utcnow().isoformat()
        profile = self.attacker_state.get(attacker_ip, {
            "session_count": 0,
            "bias_history": [],
            "response_history": [],
            "personality": "unknown",
            "frustration_level": 0.0,
            "confidence_drift": 0.0
        })

        if "profile_name" not in profile:
            profile["profile_name"] = self._generate_attacker_codename(attacker_ip, bias)

        profile["session_count"] += 1
        profile["bias_history"].append(bias)
        profile["response_history"].append(response_type)
        profile["last_seen"] = now

        if response_type in ["fake_error", "challenge"]:
            profile["frustration_level"] += 0.1
        if response_type == "fake_success":
            profile["confidence_drift"] += 0.2

        self.attacker_state[attacker_ip] = profile
        self._save_attacker_state()

    def trigger_honeypot(self, bias: str, attacker_ip: str) -> None:
        honeypots = [h for h in HONEYPOTS if h["bias"] == bias]
        if not honeypots:
            logger.warning(f"No honeypots found for bias: {bias}")
            return
        honeypot = random.choice(honeypots)
        service_name = honeypot["service"]
        try:
            service = self.docker_client.services.get(service_name)
            current_replicas = service.attrs['Spec']['Mode']['Replicated']['Replicas']
            new_replicas = current_replicas + 1
            service.scale(new_replicas)
            logger.info(f"Scaled {service_name} from {current_replicas} → {new_replicas}")
        except Exception as e:
            logger.error(f"Failed to scale {service_name}: {e}")

    def apply_response(self, bias: str, attacker_ip: str) -> bool:
        responses = self.response_templates.get(bias, [])
        if not responses:
            logger.warning(f"No responses found for bias: {bias}")
            return False
        response = random.choice(responses)
        response_type = response["type"]
        logger.info(f"Applying response: {response_type} for bias {bias}")

        try:
            if response_type == "decoy_file":
                path = f"/home/student/dcd-unified/data/cowrie/bait/{response['filename']}"
                with open(path, "w") as f:
                    f.write(response["content"])
                logger.info(f"Wrote decoy file: {path}")

            elif response_type == "delayed_response":
                time.sleep(response["delay"])
                logger.info(f"Applied delay: {response['delay']}s")

            elif response_type == "misleading_info":
                logger.info(f"[Deception] {response['message']}")

            elif response_type == "fake_error":
                logger.info(f"[Fake Error] {response['error']} — {response['hint']}")

            elif response_type == "fake_success":
                logger.info(f"[Fake Success] {response['message']} → {response['content']}")

            elif response_type == "challenge":
                logger.info(f"[Challenge Issued] {response['hint']}")

            self._update_attacker_profile(attacker_ip, bias, response_type)
            self.log_to_elasticsearch(attacker_ip, bias, response_type)
            RESPONSES_EXECUTED.inc()
            RESPONSES_SUCCESSFUL.inc()
            return True

        except Exception as e:
            logger.error(f"Error applying response: {e}")
            return False

    def log_to_elasticsearch(self, attacker_ip: str, bias: str, response_type: str):
        profile = self.attacker_state.get(attacker_ip, {})
        doc = {
            "@timestamp": datetime.utcnow().isoformat(),
            "attacker_ip": attacker_ip,
            "attacker_name": profile.get("profile_name", "unknown"),
            "response.bias": bias,
            "response.type": response_type
        }
        try:
            response = requests.post(f"{self.es_url}/dynamic-responses/_doc", json=doc, timeout=3)
            response.raise_for_status()
            logger.info(f"Logged dynamic response to ES: {response_type}")
        except Exception as e:
            logger.warning(f"[!] Skipping ELK logging, not reachable: {e}")
            # Buffering logs when ELK is down
            with open(ELK_QUEUE_FILE, "a") as f:
                f.write(json.dumps(doc) + "\n")

    def replay_elk_queue(self):
        """Attempt to resend buffered logs when ELK is back online."""
        if not os.path.exists(ELK_QUEUE_FILE):
            return

        logger.info("[*] Attempting to flush ELK queue...")
        successful = []
        try:
            with open(ELK_QUEUE_FILE, "r") as f:
                lines = f.readlines()

            for line in lines:
                try:
                    doc = json.loads(line)
                    response = requests.post(f"{self.es_url}/dynamic-responses/_doc", json=doc, timeout=3)
                    response.raise_for_status()
                    successful.append(line)
                except Exception:
                    continue  # Skip failed log entries

            # Remove successfully sent logs from the queue
            if successful:
                with open(ELK_QUEUE_FILE, "w") as f:
                    for line in lines:
                        if line not in successful:
                            f.write(line)
                logger.info(f"[+] Successfully flushed {len(successful)} entries to ELK.")
        except Exception as e:
            logger.error(f"[!] Failed to replay ELK queue: {e}")

# === Runtime Loop ===
if __name__ == "__main__":
    manager = DynamicResponseManager()
    tick = 0
    while True:
        bias = random.choice(["anchoring", "confirmation", "overconfidence"])
        attacker_ip = f"192.168.1.{random.randint(10, 254)}"
        logger.info(f"[*] Responding to {bias} bias from {attacker_ip}")
        manager.trigger_honeypot(bias, attacker_ip)
        manager.apply_response(bias, attacker_ip)

        # Periodically try to flush the ELK queue
        tick += 1
        if tick % 5 == 0:  # Every 5 iterations (5 minutes)
            manager.replay_elk_queue()

        time.sleep(60)