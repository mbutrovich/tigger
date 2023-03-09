#!/bin/bash

set -u
set -e
sudo --validate

sudo tc filter del dev enp24s0f0 egress
sudo tc qdisc del dev enp24s0f0 clsact
sudo rm -r /sys/fs/bpf/ip || true
sudo rm -r /sys/fs/bpf/tc || true
sudo rm -r /sys/fs/bpf/xdp || true
sudo rm /sys/fs/bpf/mirror_ports || true
