# BEHAVIORAL DISPATCHER

#!/usr/bin/env python3

import os
import json
import time
import logging
from datetime import datetime
from dynamic_response import DynamicResponseManager

# Logging config
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cognitive_deployer")

# Paths to honeypot logs
COWRIE_LOG = "/home/student/dcd-unified/data/cowrie/log/cowrie.json"
DIONAEA_LOG = "/home/student/dcd-unified/data/dionaea/log/dionaea.json"
ELASTICPOT_LOG = "/home/student/dcd-unified/data/elasticpot/log/elasticpot.json"

# Cache to avoid repeated triggers
seen_events = set()

# Dynamic response engine
response_manager = DynamicResponseManager()


def wait_for_services():
    import socket
    import requests
    import docker

    logger.info("Waiting for Elasticsearch and Docker to become available...")
    while True:
        try:
            requests.get("http://localhost:9200")
            docker.from_env().ping()
            logger.info("Elasticsearch and Docker are reachable")
            break
        except Exception:
            logger.warning("[!] Waiting on services...")
            time.sleep(5)


def extract_attacker_ip(log_line):
    try:
        data = json.loads(log_line)
        return data.get("src_ip") or data.get("remote_host") or "0.0.0.0"
    except:
        return "0.0.0.0"


def handle_trigger(log_line, bias):
    ip = extract_attacker_ip(log_line)
    key = f"{bias}:{ip}:{hash(log_line)}"
    if key in seen_events:
        return
    seen_events.add(key)

    logger.info(f"[Trigger] Bias: {bias}, Attacker: {ip}")
    response_manager.trigger_honeypot(bias, ip)
    response_manager.apply_response(bias, ip)


def monitor_logs():
    logger.info("[+] Starting behavioral log monitor")

    # Track file positions
    file_positions = {
        COWRIE_LOG: 0,
        DIONAEA_LOG: 0,
        ELASTICPOT_LOG: 0
    }

    while True:
        for path, bias in [(COWRIE_LOG, "anchoring"), (DIONAEA_LOG, "confirmation"), (ELASTICPOT_LOG, "overconfidence")]:
            if not os.path.exists(path):
                continue

            try:
                with open(path, "r") as f:
                    f.seek(file_positions[path])
                    for line in f:
                        if not line.strip():
                            continue
                        if "login attempt" in line or "scan" in line or "exploit" in line:
                            handle_trigger(line.strip(), bias)
                    file_positions[path] = f.tell()
            except Exception as e:
                logger.warning(f"[!] Failed to process {path}: {e}")

        time.sleep(10)


if __name__ == "__main__":
    wait_for_services()
    monitor_logs()
