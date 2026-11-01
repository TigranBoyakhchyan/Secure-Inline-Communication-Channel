#!/usr/bin/env bash
# Removes everything setup_topology.sh created.
for ns in pc1 dev1 dev2 pc2; do sudo ip netns del "$ns" 2>/dev/null || true; done
echo "Topology removed."
