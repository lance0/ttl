#!/bin/bash
set -e
ip netns add rtr
ip link add veth0 type veth peer name veth1
ip link set veth1 netns rtr
ip addr add 10.200.0.1/24 dev veth0 && ip link set veth0 up
ip netns exec rtr sysctl -qw net.ipv4.ip_forward=0
ip -n rtr addr add 10.200.0.2/24 dev veth1 && ip -n rtr link set veth1 up && ip -n rtr link set lo up
ip route add 10.250.0.0/24 via 10.200.0.2
ip netns exec rtr python3 /fakertr.py > /tmp/fakertr.log 2>&1 &
sleep 1
exec "$@"
