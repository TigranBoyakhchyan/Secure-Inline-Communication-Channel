#!/usr/bin/env bash
# Builds PC1 -> Device1 -> Device2 -> PC2 inside ONE Kali VM using
# network namespaces (each namespace behaves like a separate computer).
#
#   pc1  (eth0 10.0.1.1, MTU 1400)
#     |
#   dev1 (lan0 10.0.1.254 | wan0 10.0.12.1)   all device ports MTU 1500
#     |
#   dev2 (wan0 10.0.12.2  | lan0 10.0.2.254)
#     |
#   pc2  (eth0 10.0.2.1, MTU 1400)
#
# Why: PCs send at most 1400-byte packets; encryption adds 24 bytes, so the
# devices need room for 1424. The kernel checks the size against the OUTGOING
# port BEFORE our program runs, so every device port must stay at 1500.
#
# Usage: sudo ./setup_topology.sh
set -e
PROTECTED_PORT=5000
QUEUE=0

if [[ $EUID -ne 0 ]]; then echo "Run with sudo"; exit 1; fi

echo "[1/6] Creating namespaces (the 4 'machines')"
for ns in pc1 dev1 dev2 pc2; do ip netns add "$ns"; done

echo "[2/6] Creating virtual cables (veth pairs)"
ip link add pc1-eth0  type veth peer name dev1-lan0
ip link add dev1-wan0 type veth peer name dev2-wan0
ip link add dev2-lan0 type veth peer name pc2-eth0

# move one cable end into a namespace and give it a short name
plug() { ip link set "$1" netns "$2"; ip -n "$2" link set "$1" name "$3"; }
plug pc1-eth0  pc1  eth0
plug dev1-lan0 dev1 lan0
plug dev1-wan0 dev1 wan0
plug dev2-wan0 dev2 wan0
plug dev2-lan0 dev2 lan0
plug pc2-eth0  pc2  eth0

echo "[3/6] Assigning IP addresses and bringing links up"
ip -n pc1  addr add 10.0.1.1/24   dev eth0
ip -n dev1 addr add 10.0.1.254/24 dev lan0
ip -n dev1 addr add 10.0.12.1/24  dev wan0
ip -n dev2 addr add 10.0.12.2/24  dev wan0
ip -n dev2 addr add 10.0.2.254/24 dev lan0
ip -n pc2  addr add 10.0.2.1/24   dev eth0

# Only the PCs get MTU 1400 (so a full packet + 24 bytes still fits in 1500)
ip -n pc1  link set eth0 mtu 1400
ip -n pc2  link set eth0 mtu 1400

for ns in pc1 dev1 dev2 pc2; do ip -n "$ns" link set lo up; done
ip -n pc1  link set eth0 up
ip -n dev1 link set lan0 up; ip -n dev1 link set wan0 up
ip -n dev2 link set wan0 up; ip -n dev2 link set lan0 up
ip -n pc2  link set eth0 up

echo "[4/6] Routing: PCs use their device as gateway, devices forward"
ip -n pc1  route add default via 10.0.1.254
ip -n pc2  route add default via 10.0.2.254
ip -n dev1 route add 10.0.2.0/24 via 10.0.12.2
ip -n dev2 route add 10.0.1.0/24 via 10.0.12.1
ip netns exec dev1 sysctl -qw net.ipv4.ip_forward=1
ip netns exec dev2 sysctl -qw net.ipv4.ip_forward=1

echo "[5/6] Disabling offloads (so we always see real, finished packets)"
off() { ip netns exec "$1" ethtool -K "$2" rx off tx off tso off gso off gro off >/dev/null 2>&1 || true; }
off pc1 eth0; off dev1 lan0; off dev1 wan0; off dev2 wan0; off dev2 lan0; off pc2 eth0

echo "[6/6] Firewall: send TCP port $PROTECTED_PORT traffic to our program"
for ns in dev1 dev2; do
  # don't let connection tracking judge our resized packets
  ip netns exec "$ns" iptables -t raw -A PREROUTING -p tcp -m multiport \
       --ports "$PROTECTED_PORT" -j CT --notrack
  # hand matching forwarded packets to NFQUEUE (dropped if nobody listens!)
  ip netns exec "$ns" iptables -A FORWARD -p tcp -m multiport \
       --ports "$PROTECTED_PORT" -j NFQUEUE --queue-num "$QUEUE"
done

echo "Done. Test plain connectivity: sudo ip netns exec pc1 ping -c2 10.0.2.1"
