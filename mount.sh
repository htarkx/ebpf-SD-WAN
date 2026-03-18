#!/bin/bash
sudo ./bin/sdwan-tc apply \
  --iface wg0 \
  --obj ./bpf/mark_delegate.o \
  --mark 0x66 \
  --dns-redirect \
  --dns-ip 10.66.67.1 \
  --dns-port 53 \
  --pin /sys/fs/bpf/ebpf-sd-wan

tc filter show dev wg0 ingress
tc filter show dev wg0 egress
sudo ./bin/sdwan-tc stats --pin /sys/fs/bpf/ebpf-sd-wan
#sudo ./bin/sdwan-tc detach --iface wg0
