#!/bin/bash

set -u
set -e
sudo --validate

sudo tc qdisc add dev enp24s0f0 clsact
sudo tc filter add dev enp24s0f0 egress bpf direct-action obj tc_test.bpf.o sec 'classifier/tc_test'
sudo bpftool map pin name mirror_ports /sys/fs/bpf/mirror_ports
