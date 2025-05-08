#!/bin/bash

# Start cAdvisor
echo "[*] Starting cAdvisor..."
docker run -d \
  --name cadvisor \
  --restart=always \
  -p 8080:8080 \
  --volume=/:/rootfs:ro \
  --volume=/var/run:/var/run:ro \
  --volume=/sys:/sys:ro \
  --volume=/var/lib/docker/:/var/lib/docker:ro \
  --privileged \
  gcr.io/cadvisor/cadvisor

# Start Node Exporter
echo "[*] Starting Node Exporter..."
docker run -d \
  --name node_exporter \
  --restart=always \
  --net=host \
  quay.io/prometheus/node-exporter

echo "[+] Both exporters are running."
